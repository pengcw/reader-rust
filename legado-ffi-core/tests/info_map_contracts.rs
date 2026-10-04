use reader_parser::{executor::execute, parser::js::eval_js};
use serde_json::{json, Value};

fn run(script: &str, state: Option<Value>, library: Option<&str>) -> Value {
    let source = json!({"bookSourceUrl":"https://info-map.test/a#one", "exploreUrl":format!("@js:{script}"), "jsLib":library});
    let mut request = json!({"api":2,"op":"explore_kinds","params":{}});
    if let Some(state) = state {
        request["infoMap"] = state;
    }
    serde_json::from_str(&execute(&source.to_string(), &request.to_string())).unwrap()
}

#[test]
fn map_roundtrip_is_independent_of_session_and_does_not_leak_into_other_evaluations() {
    let first = run(
        "infoMap.put('分类','推荐'); [{title:infoMap.get('分类')}];",
        None,
        None,
    );
    assert_eq!(first["ok"], true, "{first}");
    let second = run(
        "[{title:infoMap.get('分类')}];",
        Some(first["infoMap"].clone()),
        None,
    );
    assert_eq!(second["data"][0]["title"], "推荐");
    assert_eq!(second["session"]["variables"].get("分类"), None);
    assert_eq!(
        eval_js("typeof infoMap", "", "https://other.test").unwrap(),
        "undefined"
    );
    let fresh = run("[{title:String(infoMap.isEmpty())}];", None, None);
    assert_eq!(fresh["data"][0]["title"], "true");
}

#[test]
fn map_keys_cannot_override_methods_or_pollute_prototypes() {
    let result = run("for(const key of ['get','put','save','__proto__','constructor','中文']) infoMap.put(key,'值'); [{title:infoMap.get('__proto__')}];", None, None);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["infoMap"]["values"]["get"], "值");
    assert_eq!(result["infoMap"]["values"]["__proto__"], "值");
    assert_eq!(result["data"][0]["title"], "值");
}

#[test]
fn mutable_view_and_replacement_keep_old_map_detached() {
    let result = run("const old=infoMap.get(); old.put('old','one'); infoMap.set({new:'two'}); old.put('old','changed'); const previous=infoMap.put('new','three'); infoMap.putAll({extra:'four'}); infoMap.remove('extra'); [{title:previous+':'+infoMap.size+':'+infoMap.containsValue('three')}];", None, None);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["infoMap"]["values"], json!({"new":"three"}));
    assert_eq!(result["data"][0]["title"], "two:1:true");
}

#[test]
fn reentrant_helpers_keep_existing_map_views_attached() {
    let result = run("const view=infoMap.get(); if(java.getString('@js:result','seed') !== 'seed') throw new Error('nested helper failed'); view.put('after','yes'); [{title:infoMap.get('after')}];", None, None);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"][0]["title"], "yes");
}

#[test]
fn library_can_access_map_and_result_fallback_is_preserved() {
    let result = run(
        "result=[{title:infoMap.get('library')}]; void 0;",
        None,
        Some("infoMap.put('library','ready');"),
    );
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(result["data"][0]["title"], "ready");
}

#[test]
fn save_marks_state_and_false_cancels_without_clearing_values() {
    let first = run("infoMap.put('n','one'); infoMap.save(60); [];", None, None);
    assert_eq!(first["infoMap"]["needSave"], true);
    assert_eq!(first["infoMap"]["saveTime"], 60);
    let second = run(
        "infoMap.save(9,false); [];",
        Some(first["infoMap"].clone()),
        None,
    );
    assert_eq!(second["infoMap"]["needSave"], false);
    assert_eq!(second["infoMap"]["saveTime"], 9);
    assert_eq!(second["infoMap"]["values"]["n"], "one");
}

#[test]
fn failed_classification_does_not_publish_unsaved_changes() {
    for script in [
        "infoMap.put('n','bad'); throw new Error('failed');",
        "infoMap.put('n','bad'); '[invalid';",
        "infoMap.saveNow(); [];",
    ] {
        let result = run(script, None, None);
        assert_eq!(result["ok"], false, "{result}");
        assert!(result.get("infoMap").is_none());
    }
}

#[test]
fn invalid_state_is_rejected_before_script_execution() {
    for state in [
        json!({"values":[],"needSave":false,"saveTime":0}),
        json!({"values":{"n":1},"needSave":false,"saveTime":0}),
        json!({"values":{},"needSave":false,"saveTime":-1}),
    ] {
        let result = run("throw new Error('must not run');", Some(state), None);
        assert_eq!(result["ok"], false);
        assert_eq!(result["error"]["kind"], "invalid_request");
    }
}
