// Evaluation-local node facade; native callbacks own the shared read-only tree.
(() => {
    const nativeQuery = globalThis.__readerDomQuery;
    const nodes = new WeakMap();
    const collections = new WeakMap();
    const query = (operation, path, argument = '') =>
        JSON.parse(nativeQuery(operation, JSON.stringify(path), String(argument)));
    const collection = descriptors => {
        const items = descriptors.map(node);
        const paths = items.map(item => nodes.get(item));
        const outerHtml = () => paths.map(path => query('outerHtml', path)).join('');
        collections.set(items, paths);
        items.first = () => items.length ? items[0] : null;
        items.get = index => Number.isInteger(Number(index)) && Number(index) >= 0
            && Number(index) < items.length ? items[Number(index)] : null;
        items.size = () => items.length;
        items.toArray = () => Array.from(items);
        items.outerHtml = outerHtml;
        items.toString = outerHtml;
        return items;
    };
    const node = descriptor => {
        if (descriptor == null) return null;
        const path = descriptor.__readerDomNode;
        const object = {
            attr: name => query('attr', path, name),
            hasAttr: name => query('hasAttr', path, name),
            hasClass: name => {
                const target = String(name).toLowerCase();
                return String(query('attr', path, 'class')).split(/\s+/)
                    .some(value => value.toLowerCase() === target);
            },
            text: () => query('text', path),
            ownText: () => query('ownText', path),
            html: () => query('html', path),
            outerHtml: () => query('outerHtml', path),
            select: selector => collection(query('select', path, selector)),
            selectFirst: selector => collection(query('select', path, selector)).first(),
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
        if (path !== undefined) return query('outerHtml', path);
        const paths = collections.get(value);
        return paths === undefined
            ? undefined
            : paths.map(item => query('outerHtml', item)).join('');
    };
})()
