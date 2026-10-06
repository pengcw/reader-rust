// Evaluation-local node facade; native callbacks own the shared read-only tree.
(() => {
    const nativeQuery = globalThis.__readerDomQuery;
    const nodes = new WeakMap();
    const query = (operation, path, argument = '') =>
        JSON.parse(nativeQuery(operation, JSON.stringify(path), String(argument)));
    const collection = descriptors => {
        const items = descriptors.map(node);
        items.first = () => items.length ? items[0] : null;
        items.get = index => Number.isInteger(Number(index)) && Number(index) >= 0
            && Number(index) < items.length ? items[Number(index)] : null;
        items.size = () => items.length;
        items.toArray = () => Array.from(items);
        return items;
    };
    const node = descriptor => {
        if (descriptor == null) return null;
        const path = descriptor.__readerDomNode;
        const object = {
            attr: name => query('attr', path, name),
            hasAttr: name => query('hasAttr', path, name),
            hasClass: name => String(query('attr', path, 'class')).split(/\s+/).includes(String(name)),
            text: () => query('text', path),
            html: () => query('html', path),
            outerHtml: () => query('outerHtml', path),
            select: selector => collection(query('select', path, selector)),
            parent: () => node(query('parent', path)),
            children: () => collection(query('children', path)),
            elementSiblingIndex: () => query('elementSiblingIndex', path),
            toString: () => query('outerHtml', path),
            toJSON: () => query('outerHtml', path)
        };
        nodes.set(object, path);
        return object;
    };
    globalThis.result = node(globalThis.result);
    return value => {
        const path = nodes.get(value);
        return path === undefined ? undefined : query('outerHtml', path);
    };
})()
