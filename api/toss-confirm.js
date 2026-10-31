/**
 * 토스페이먼츠 결제 승인 (Vercel Serverless Function)
 *
 * 결제위젯에서 인증이 끝나면 브라우저가 이 주소로 paymentKey·orderId·amount 를 보냅니다.
 * 여기서 주문번호에 담긴 수량으로 금액을 다시 계산해 맞는지 확인한 뒤에만
 * 토스에 최종 승인을 요청합니다. (승인 전에는 고객 카드에서 돈이 빠져나가지 않음)
 *
 * Vercel → Settings → Environment Variables
 *   TOSS_SECRET_KEY   토스 결제위젯 연동 키의 시크릿 키 (live_gsk_...)
 */

// ※ 가격·배송비를 바꾸면 index.html 의 PRODUCTS / SHIP_FEE / FREE_MIN 도 같이 바꿔야 합니다.
const PRICES = { '2L': 25000, '340': 5500 };
const SHIP_FEE = 3000;
const FREE_MIN = 60000;
const MAX_QTY = 20;

// 주문번호 형식: hd-<시각>-<2L수량>x<340mL수량>   예) hd-1793000000000-2x3
const ORDER_RE = /^hd-(\d{10,16})-(\d{1,2})x(\d{1,2})$/;

function calcTotal(q2L, q340) {
  const subtotal = q2L * PRICES['2L'] + q340 * PRICES['340'];
  const ship = subtotal >= FREE_MIN ? 0 : SHIP_FEE;
  return { subtotal, ship, total: subtotal + ship };
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, code: 'METHOD_NOT_ALLOWED', message: 'POST 요청만 받습니다.' });
  }

  const secret = process.env.TOSS_SECRET_KEY;
  if (!secret) {
    return res.status(500).json({ ok: false, code: 'NOT_CONFIGURED', message: '결제 설정이 아직 완료되지 않았습니다.' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body || '{}'); } catch (_) { body = {}; }
  }
  const { paymentKey, orderId, amount } = body || {};

  const m = ORDER_RE.exec(String(orderId || ''));
  if (!paymentKey || !m) {
    return res.status(400).json({ ok: false, code: 'INVALID_REQUEST', message: '주문 정보가 올바르지 않습니다.' });
  }

  const q2L = parseInt(m[2], 10);
  const q340 = parseInt(m[3], 10);
  if (q2L + q340 < 1 || q2L > MAX_QTY || q340 > MAX_QTY) {
    return res.status(400).json({ ok: false, code: 'INVALID_QTY', message: '주문 수량이 올바르지 않습니다.' });
  }

  const { subtotal, ship, total } = calcTotal(q2L, q340);
  if (Number(amount) !== total) {
    return res.status(400).json({ ok: false, code: 'AMOUNT_MISMATCH', message: '결제 금액이 주문 금액과 다릅니다.' });
  }

  let tossRes, data;
  try {
    tossRes = await fetch('https://api.tosspayments.com/v1/payments/confirm', {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(secret + ':').toString('base64'),
        'Content-Type': 'application/json',
        'Idempotency-Key': orderId,
      },
      body: JSON.stringify({ paymentKey, orderId, amount: total }),
    });
    data = await tossRes.json();
  } catch (err) {
    return res.status(502).json({ ok: false, code: 'NETWORK_ERROR', message: '결제 승인 서버에 연결하지 못했습니다.' });
  }

  if (!tossRes.ok) {
    return res.status(400).json({ ok: false, code: data && data.code, message: (data && data.message) || '결제 승인에 실패했습니다.' });
  }

  return res.status(200).json({
    ok: true,
    orderId: data.orderId,
    paymentKey: data.paymentKey,
    totalAmount: data.totalAmount,
    method: data.method,
    easyPay: data.easyPay ? data.easyPay.provider : null,
    approvedAt: data.approvedAt,
    receiptUrl: data.receipt ? data.receipt.url : null,
    items: { '2L': q2L, '340': q340 },
    subtotal,
    ship,
  });
};

module.exports.calcTotal = calcTotal;
