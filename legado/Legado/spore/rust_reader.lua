local H = require("Legado/Helper")
local Reader3 = require("Legado.spore.reader3")

-- reader-rust 后端适配器:与 reader3 接口高度一致,继承 reader3 实现,
-- 仅重写存在差异的接口(字段名 / 返回结构 / 缺失接口)
local M = Reader3:extend{
    name = "rust_reader",
    client = nil,
    settings = nil,
}

-- 章节列表:reader-rust 返回 {title,url,index,tag,isVip,isPay,isVolume},
-- 上层依赖 chapters_index 字段,这里做字段映射
function M:getChapterList(bookinfo, callback)
    if not (H.is_tbl(bookinfo) and bookinfo.bookUrl) then
        return nil, "参数错误"
    end
    local bookUrl = bookinfo.bookUrl
    return self:handleResponse(function()
        return self.client:getChapterList({
            url = bookUrl,
            v = os.time(),
        })
    end, function(res)
        local list = res.data
        if not H.is_tbl(list) then
            return nil, "获取目录失败"
        end
        for _, ch in ipairs(list) do
            if H.is_tbl(ch) then
                ch.chapters_index = ch.index
                ch.is_volume = ch.isVolume
                ch.is_vip = ch.isVip
            end
        end
        return list
    end, { timeouts = {10, 18} }, 'getChapterList')
end

-- 进度:reader-rust 请求结构只认 position 字段,不认 durChapterPos
function M:saveBookProgress(chapter, callback)
    if not (H.is_str(chapter.name) and H.is_str(chapter.bookUrl)) then
        return nil, '参数错误'
    end
    local chapters_index = chapter.chapters_index
    return self:handleResponse(function()
        local timestamp = os.time()
        return self.client:saveBookProgress({
            name = chapter.name,
            author = chapter.author or '',
            position = 0,
            durChapterIndex = chapters_index,
            durChapterTime = timestamp * 1000,
            durChapterTitle = chapter.title or '',
            index = chapters_index,
            url = chapter.bookUrl,
            v = timestamp,
        })
    end, callback, { timeouts = {3, 5} }, 'saveBookProgress')
end

-- 多源搜索:reader-rust 一次性返回合并数组且无服务端分页,
-- 包装为上层期望的 {list, lastIndex};lastIndex=-1 表示没有更多
function M:searchBookMulti(options, callback)
    if not (H.is_tbl(options) and H.is_str(options.search_text) and options.search_text ~= '') then
        return nil, "输入参数错误"
    end
    local search_text = options.search_text
    local concurrentCount = options.concurrent_count or 32
    return self:handleResponse(function()
        return self.client:searchBookMulti({
            key = search_text,
            bookSourceGroup = '',
            concurrentCount = concurrentCount,
            lastIndex = -1,
            searchSize = 100,
            v = os.time(),
        })
    end, function(res)
        local list = res.data
        if not H.is_tbl(list) then
            return nil, "服务器返回数据错误"
        end
        return { list = list, lastIndex = -1 }
    end, { timeouts = {60, 80} }, 'searchBookMulti')
end

-- 可用书源:reader-rust 无 searchBookSource 分页续查接口,一次性返回全部
function M:getAvailableBookSource(options, callback)
    if not (H.is_tbl(options) and H.is_str(options.book_url)) then
        return nil, '获取可用书源参数错误'
    end
    local bookUrl = options.book_url
    return self:handleResponse(function()
        return self.client:getAvailableBookSource({
            url = bookUrl,
            refresh = 0,
            v = os.time(),
        })
    end, function(res)
        local list = res.data
        if not H.is_tbl(list) then
            return nil, '返回数据错误'
        end
        return { list = list, lastIndex = -1 }
    end, { timeouts = {30, 50} }, 'getAvailableBookSource')
end

-- Backend.lua 的 NEED_LOGIN 分支会调用 reader3Token(reader3 适配器未实现),这里补齐
function M:reader3Token()
    if self.tokenManager then
        self.tokenManager:clear()
    end
end

return M
