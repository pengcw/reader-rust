//! HTML XPath nodes support selected default extractors without changing XPath/XML semantics.
use reader_parser::model::book_source::BookSource;
use reader_parser::parser::rule_engine::RuleEngine;
use serde_json::json;

const BASE: &str = "https://fixture.test/book/1/";

fn source(name: &str, url: &str, author: &str) -> BookSource {
    serde_json::from_value(json!({"bookSourceUrl":BASE, "bookSourceName":"XPath field fixture",
        "ruleSearch":{"bookList":"//a[@class='book']", "name":name, "bookUrl":url, "author":author}})).unwrap()
}

#[test]
fn html_xpath_nodes_extract_text_and_href_from_selected_element() {
    let books = RuleEngine::new().unwrap().search_books(
        &source("text", "href", "ownText"),
        "<a class='book' href='/one'>Own <b>Nested</b></a><a class='book' href='/two'>Second</a>",
        BASE,
    );
    assert_eq!(books.len(), 2);
    assert_eq!(books[0].name, "Own Nested");
    assert_eq!(books[0].author, "Own");
    assert_eq!(books[0].book_url, "https://fixture.test/one");
    assert_eq!(books[1].name, "Second");
}

#[test]
fn html_xpath_text_normalization_preserves_ideographic_spaces_and_attribute_whitespace() {
    let books = RuleEngine::new().unwrap().search_books(
        &source("text", "href", "title"),
        "<a class='book' href='/one' title='two  spaces'>书　名&nbsp;<b>\u{200b}尾</b></a>",
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "书　名 尾");
    assert_eq!(books[0].author, "two  spaces");
}

#[test]
fn html_xpath_default_fields_keep_combination_and_postprocessing() {
    let books = RuleEngine::new().unwrap().search_books(
        &source(
            "text##广告##",
            "href",
            "title&&data-note@js:result.toUpperCase()",
        ),
        "<a class='book' href='/one' title='first' data-note='second'>广告正文</a>",
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "正文");
    assert_eq!(books[0].author, "FIRST\nSECOND");
}

#[test]
fn explicit_css_fields_select_inside_original_html_node() {
    let books = RuleEngine::new().unwrap().search_books(
        &source("@css:b@text", "@css:href", "@css:i@text"),
        "<a class='book' href='/one'><b>Title</b><i>Author</i></a>",
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "Title");
    assert_eq!(books[0].author, "Author");
    assert_eq!(books[0].book_url, "https://fixture.test/one");
}

#[test]
fn missing_default_attribute_does_not_read_same_named_child_element() {
    let books = RuleEngine::new().unwrap().search_books(
        &source("text", "href", "src"),
        "<a class='book'><href>not-an-attribute</href>Title</a>",
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].author, "");
    assert_eq!(books[0].book_url, BASE);
}

#[test]
fn explicit_xpath_preserves_ancestors_and_attribute_context() {
    let books = RuleEngine::new().unwrap().search_books(&source("@xpath:../@data-name", "@href", "@xpath:../following-sibling::p/text()"),
        "<section data-name='From parent'><a class='book' href='/one'>Link</a></section><p>Sibling</p>", BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "From parent");
    assert_eq!(books[0].author, "Sibling");
    assert_eq!(books[0].book_url, "https://fixture.test/one");
}

#[test]
fn table_xpath_nodes_keep_attributes_and_children_for_default_and_css_fields() {
    let source: BookSource = serde_json::from_value(json!({"bookSourceUrl":BASE,
        "ruleSearch":{"bookList":"//td", "name":"ownText", "bookUrl":"data-url", "author":"@css:b@text"}})).unwrap();
    let books = RuleEngine::new().unwrap().search_books(
        &source,
        "<table><tr><td data-url='/cell'>Cell <b>Author</b></td></tr></table>",
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "Cell");
    assert_eq!(books[0].author, "Author");
    assert_eq!(books[0].book_url, "https://fixture.test/cell");
}

#[test]
fn xml_bare_fields_continue_to_select_child_elements() {
    let source: BookSource = serde_json::from_value(json!({"bookSourceUrl":BASE,
        "ruleSearch":{"bookList":"@xpath://Book", "name":"Title", "bookUrl":"Url", "author":"text"}})).unwrap();
    let books = RuleEngine::new().unwrap().search_books(&source,
        "<?xml version='1.0'?><Root><Book><Title>XML title</Title><Url>/xml</Url><text>XML child</text></Book></Root>", BASE);
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "XML title");
    assert_eq!(books[0].author, "XML child");
    assert_eq!(books[0].book_url, "https://fixture.test/xml");
}

#[test]
fn explicit_xpath_named_text_child_is_not_a_default_extractor() {
    let books = RuleEngine::new().unwrap().search_books(
        &source("@xpath:text", "@href", "@xpath:href"),
        "<a class='book' href='/one'><text>Child only</text><href>Child URL</href>Other</a>",
        BASE,
    );
    assert_eq!(books.len(), 1);
    assert_eq!(books[0].name, "Child only");
    assert_eq!(books[0].author, "Child URL");
}
