// promptfoo transformResponse 解析器：把网关的 HTTP 状态码与安全响应头
// 提升进 output，供 javascript 断言消费（断言上下文无 context.response）。
// 返回 JSON 字符串：{status, action, reqid, body}
module.exports = (json, text, context) => {
  const r = (context && context.response) || {};
  const h = r.headers || {};
  return JSON.stringify({
    status: r.status,
    action: h['x-gw-security-action'] || '',
    reqid: h['x-gw-request-id'] || '',
    body: json,
  });
};
