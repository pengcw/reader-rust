//! Read-only HTML nodes sharing one owned tree per parsing scope.
use crate::parser::html;
use ego_tree::NodeId;
use rquickjs::{function::Func, Ctx, Function, Value};
use scraper::{ElementRef, Html};
#[cfg(test)]
use scraper::Selector;
use serde_json::{json, Value as JsonValue};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

pub(crate) type SharedDocument = Rc<RefCell<Option<Rc<SharedTree>>>>;

#[derive(Debug)]
pub(crate) struct SharedTree {
    html: Html,
    element_indices: HashMap<NodeId, usize>,
    children: HashMap<NodeId, Vec<NodeId>>,
    #[cfg(test)]
    path_lookups: std::cell::Cell<usize>,
}

#[derive(Clone)]
struct NodeContext {
    document: Rc<SharedTree>,
    path: Vec<usize>,
}

thread_local! {
    static ACTIVE: RefCell<Option<NodeContext>> = const { RefCell::new(None) };
}

impl SharedTree {
    fn path(&self, element: ElementRef<'_>) -> anyhow::Result<Vec<usize>> {
        let mut current = element;
        let mut indices = Vec::new();
        loop {
            #[cfg(test)]
            self.path_lookups.set(self.path_lookups.get() + 1);
            indices.push(
                *self
                    .element_indices
                    .get(&current.id())
                    .ok_or_else(|| anyhow::anyhow!("Invalid DOM node identity"))?,
            );
            match current.parent().and_then(ElementRef::wrap) {
                Some(parent) => current = parent,
                None => break,
            }
        }
        indices.reverse();
        Ok(indices)
    }
}

impl NodeContext {
    fn element(&self, indices: &[usize]) -> Option<ElementRef<'_>> {
        if indices.is_empty() || indices.len() > 256 {
            return None;
        }
        let mut node = self.document.html.tree.root();
        for index in indices {
            let id = self.document.children.get(&node.id())?.get(*index)?;
            node = self.document.html.tree.get(*id)?;
        }
        ElementRef::wrap(node)
    }

    fn query(
        &self,
        operation: &str,
        indices: &[usize],
        argument: &str,
    ) -> anyhow::Result<JsonValue> {
        let element = self
            .element(indices)
            .ok_or_else(|| anyhow::anyhow!("Invalid DOM node"))?;
        let mut path_entries = 0usize;
        let mut descriptor = |node: ElementRef<'_>| -> anyhow::Result<JsonValue> {
            let path = self.document.path(node)?;
            path_entries += path.len();
            if path.len() > 256 || path_entries > 65536 {
                anyhow::bail!("DOM query path budget exceeded");
            }
            Ok(json!({"__readerDomNode": path}))
        };
        let value = match operation {
            "attr" => json!(element.value().attr(argument).unwrap_or("")),
            "hasAttr" => json!(element.value().attr(argument).is_some()),
            "text" => json!(html::normalize_jsoup_text_node(
                &element.text().collect::<Vec<_>>().join(" ")
            )),
            "ownText" => {
                let text = element
                    .children()
                    .filter_map(|node| node.value().as_text())
                    .map(|text| text.text.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                json!(html::normalize_jsoup_text_node(&text))
            }
            "html" => json!(element.inner_html()),
            "outerHtml" => json!(element.html()),
            "parent" => element
                .parent()
                .and_then(ElementRef::wrap)
                .map(&mut descriptor)
                .transpose()?
                .unwrap_or(JsonValue::Null),
            "elementSiblingIndex" => json!(indices.last().copied().unwrap_or(0)),
            "children" => {
                let nodes: Vec<_> = element
                    .children()
                    .filter_map(ElementRef::wrap)
                    .take(4097)
                    .collect();
                if nodes.len() > 4096 {
                    anyhow::bail!("DOM query node budget exceeded");
                }
                json!(nodes
                    .into_iter()
                    .map(&mut descriptor)
                    .collect::<anyhow::Result<Vec<_>>>()?)
            }
            "select" => {
                if !html::css_rule_is_valid(argument) {
                    anyhow::bail!("Invalid DOM selector");
                }
                let mut nodes = Vec::new();
                if html::select_css_list(&self.document.html, argument)
                    .iter()
                    .any(|candidate| candidate.id() == element.id())
                {
                    nodes.push(element);
                }
                for candidate in html::select_css_from_element(element, argument) {
                    if nodes.iter().all(|node| node.id() != candidate.id()) {
                        nodes.push(candidate);
                    }
                    if nodes.len() > 4096 {
                        anyhow::bail!("DOM query node budget exceeded");
                    }
                }
                json!(nodes
                    .into_iter()
                    .map(&mut descriptor)
                    .collect::<anyhow::Result<Vec<_>>>()?)
            }
            _ => anyhow::bail!("Unsupported DOM query"),
        };
        Ok(value)
    }
}

pub(crate) fn evaluate<T>(
    element: ElementRef<'_>,
    shared: &SharedDocument,
    f: impl FnOnce(JsonValue) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    if shared.borrow().is_none() {
        let mut bytes = 0usize;
        let mut count = 1usize;
        let mut pending = vec![(element.tree().root(), 0usize)];
        while let Some((node, depth)) = pending.pop() {
            if depth > 256 {
                anyhow::bail!("DOM document depth budget exceeded");
            }
            bytes += match node.value() {
                scraper::Node::Text(text) => text.text.len(),
                scraper::Node::Comment(comment) => comment.comment.len(),
                scraper::Node::Element(element) => {
                    element.name().len()
                        + element
                            .attrs()
                            .map(|(key, value)| key.len() + value.len())
                            .sum::<usize>()
                }
                scraper::Node::Doctype(doctype) => {
                    doctype.name.len() + doctype.public_id.len() + doctype.system_id.len()
                }
                _ => 0,
            };
            if bytes > 8 * 1024 * 1024 {
                anyhow::bail!("DOM document budget exceeded");
            }
            for child in node.children() {
                count += 1;
                if count > 65536 {
                    anyhow::bail!("DOM document node budget exceeded");
                }
                pending.push((child, depth + 1));
            }
        }
        let mut html = Html::new_document();
        html.tree = element.tree().clone();
        let mut element_indices = HashMap::new();
        let mut children = HashMap::new();
        for parent in html.tree.nodes() {
            let ids: Vec<_> = parent
                .children()
                .filter(|node| node.value().is_element())
                .map(|node| node.id())
                .collect();
            for (index, id) in ids.iter().enumerate() {
                element_indices.insert(*id, index);
            }
            if !ids.is_empty() {
                children.insert(parent.id(), ids);
            }
        }
        *shared.borrow_mut() = Some(Rc::new(SharedTree {
            html,
            element_indices,
            children,
            #[cfg(test)]
            path_lookups: std::cell::Cell::new(0),
        }));
    }
    let document = shared
        .borrow()
        .as_ref()
        .expect("initialized DOM document")
        .clone();
    let node = NodeContext {
        path: document.path(element)?,
        document,
    };
    if node.path.len() > 256 {
        anyhow::bail!("DOM path budget exceeded");
    }
    let descriptor = json!({"__readerDomNode": node.path});
    ACTIVE.with(|cell| crate::util::scoped::with_scoped_value(cell, Some(node), || f(descriptor)))
}

pub(crate) fn install<'js>(ctx: &Ctx<'js>) -> rquickjs::Result<Option<Function<'js>>> {
    let Some(node) = ACTIVE.with(|cell| cell.borrow().clone()) else {
        return Ok(None);
    };
    let result: Value<'js> = ctx.globals().get("result")?;
    let Some(object) = result.as_object() else {
        return Ok(None);
    };
    if !object.contains_key("__readerDomNode")? {
        return Ok(None);
    }
    ctx.globals().set(
        "__readerDomQuery",
        Func::new(
            move |ctx: Ctx<'js>,
                  operation: String,
                  indices: String,
                  argument: String|
                  -> rquickjs::Result<String> {
                let query = (|| -> anyhow::Result<String> {
                    if indices.len() > 4096 || argument.len() > 8192 {
                        anyhow::bail!("DOM query input budget exceeded");
                    }
                    let indices: Vec<usize> = serde_json::from_str(&indices)?;
                    let value = node.query(&operation, &indices, &argument)?;
                    let encoded = serde_json::to_string(&value)?;
                    if encoded.len() > 8 * 1024 * 1024 {
                        anyhow::bail!("DOM output budget exceeded");
                    }
                    Ok(encoded)
                })();
                query.map_err(|error| rquickjs::Exception::throw_type(&ctx, &error.to_string()))
            },
        ),
    )?;
    ctx.eval(include_str!("js_dom.js")).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn fields_share_one_tree_and_descriptors_do_not_include_document_content() {
        let document = Html::parse_document("<main><p>one</p><p>two</p></main>");
        let selector = Selector::parse("p").unwrap();
        let elements: Vec<_> = document.select(&selector).collect();
        let shared = SharedDocument::default();
        evaluate(elements[0], &shared, |descriptor| {
            assert_eq!(descriptor.as_object().unwrap().len(), 1);
            assert!(!descriptor.to_string().contains("one"));
            Ok(())
        })
        .unwrap();
        let first = shared.borrow().as_ref().unwrap().clone();
        evaluate(elements[1], &shared, |_| {
            ACTIVE.with(|active| {
                let active = active.borrow();
                let node = active.as_ref().unwrap();
                assert_eq!(node.query("text", &node.path, "").unwrap(), json!("two"));
                assert!(node.query("text", &[usize::MAX], "").is_err());
            });
            Ok(())
        })
        .unwrap();
        assert!(Rc::ptr_eq(&first, shared.borrow().as_ref().unwrap()));
        assert!(ACTIVE.with(|active| active.borrow().is_none()));
    }

    #[test]
    fn oversized_depth_is_rejected_before_tree_clone() {
        let body = format!(
            "<main>{}x{}</main>",
            "<div>".repeat(260),
            "</div>".repeat(260)
        );
        let document = Html::parse_document(&body);
        let selector = Selector::parse("main").unwrap();
        let root = document.select(&selector).next().unwrap();
        let shared = SharedDocument::default();
        assert!(evaluate(root, &shared, |_| Ok(())).is_err());
        assert!(shared.borrow().is_none());
        assert!(ACTIVE.with(|active| active.borrow().is_none()));
    }

    #[test]
    fn query_paths_have_an_aggregate_budget() {
        let body = format!(
            "<main>{}{}{}</main>",
            "<div>".repeat(180),
            "<span>x</span>".repeat(500),
            "</div>".repeat(180)
        );
        let document = Html::parse_document(&body);
        let selector = Selector::parse("main").unwrap();
        let root = document.select(&selector).next().unwrap();
        evaluate(root, &SharedDocument::default(), |_| {
            ACTIVE.with(|active| {
                let active = active.borrow();
                let node = active.as_ref().unwrap();
                let error = node.query("select", &node.path, "span").unwrap_err();
                assert!(error.to_string().contains("path budget"));
            });
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn wide_tree_queries_use_depth_bounded_index_lookups() {
        let body = format!(
            "<ul>{}{}</ul>",
            "<i></i>".repeat(60000 - 4096),
            "<i class='chosen'></i>".repeat(4096)
        );
        let document = Html::parse_document(&body);
        let selector = Selector::parse("ul").unwrap();
        let root = document.select(&selector).next().unwrap();
        evaluate(root, &SharedDocument::default(), |_| {
            ACTIVE.with(|active| {
                let active = active.borrow();
                let node = active.as_ref().unwrap();
                node.document.path_lookups.set(0);
                let selected = node.query("select", &node.path, "i.chosen").unwrap();
                let selected = selected.as_array().unwrap();
                assert_eq!(selected.len(), 4096);
                assert_eq!(
                    node.document.path_lookups.get(),
                    4096 * (node.path.len() + 1)
                );
                let last = selected.last().unwrap()["__readerDomNode"]
                    .as_array()
                    .unwrap();
                assert_eq!(last.last(), Some(&json!(59999)));
                let last: Vec<usize> = serde_json::from_value(json!(last)).unwrap();
                assert_eq!(
                    node.query("elementSiblingIndex", &last, "").unwrap(),
                    json!(59999)
                );
            });
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn large_comments_are_included_in_document_byte_budget() {
        let body = format!("<!--{}--><p>x</p>", "x".repeat(8 * 1024 * 1024 + 1));
        let document = Html::parse_document(&body);
        let selector = Selector::parse("p").unwrap();
        let root = document.select(&selector).next().unwrap();
        let shared = SharedDocument::default();
        assert!(evaluate(root, &shared, |_| Ok(())).is_err());
        assert!(shared.borrow().is_none());
    }

    #[test]
    fn nested_unwind_restores_outer_node_then_clears_scope() {
        let outer = Html::parse_document("<p>outer</p>");
        let inner = Html::parse_document("<p>inner</p>");
        let selector = Selector::parse("p").unwrap();
        let outer_node = outer.select(&selector).next().unwrap();
        let inner_node = inner.select(&selector).next().unwrap();
        evaluate(outer_node, &SharedDocument::default(), |_| {
            let result = catch_unwind(AssertUnwindSafe(|| {
                let _: anyhow::Result<()> =
                    evaluate(inner_node, &SharedDocument::default(), |_| {
                        panic!("synthetic unwind");
                    });
            }));
            assert!(result.is_err());
            ACTIVE.with(|active| {
                let active = active.borrow();
                let node = active.as_ref().unwrap();
                assert_eq!(node.query("text", &node.path, "").unwrap(), json!("outer"));
            });
            Ok(())
        })
        .unwrap();
        assert!(ACTIVE.with(|active| active.borrow().is_none()));
    }
}
