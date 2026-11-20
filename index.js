const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();

// ضروري على Render لقراءة عنوان الـ IP الحقيقي خلف البروكسي
app.set('trust proxy', 1);

// تهيئة Firebase Admin
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  console.error('❌ FIREBASE_SERVICE_ACCOUNT environment variable is missing!');
}

const db = admin.firestore();

// الحد الأقصى للمكافأة في عرض واحد لمنع القيم الشاذة
const MAX_SINGLE_REWARD = 500000;

// 🛡️ حماية ضد الإغراق (أقصى حد 60 طلباً لكل IP في الدقيقة)
const postbackLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests',
});

// 🛡️ مقارنة آمنة لكلمات السر لمنع هجمات التوقيت (Timing Attacks)
function isValidSecret(provided, expected) {
  if (!provided || !expected) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// تنظيف المعرفات قبل استخدامها كأسماء مستندات في Firestore
function sanitizeDocId(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_');
}

app.get('/', (req, res) => {
  res.send('Game Rewards Postback Server is Running Securely!');
});

// دالة موحدة وآمنة لإضافة العملات ومنع التكرار
async function creditUserCoins(uid, amount, network, offerId) {
  const numericAmount = Number(amount);
  const coinsToAdd = Math.floor(numericAmount);

  if (!uid || !Number.isFinite(numericAmount) || coinsToAdd <= 0 || coinsToAdd > MAX_SINGLE_REWARD) {
    throw new Error('Invalid userId or reward amount');
  }

  const safeUid = sanitizeDocId(uid);
  const safeOfferId = sanitizeDocId(offerId || `tx_${Date.now()}`);
  const txId = `${network}_${safeOfferId}_${safeUid}`;

  const txRef = db.collection('completed_offers').doc(txId);
  const userRef = db.collection('users').doc(uid);

  await db.runTransaction(async (t) => {
    const txDoc = await t.get(txRef);
    if (txDoc.exists) {
      console.log(`⚠️ Duplicate postback ignored: ${txId}`);
      return; // العرض محتسب مسبقاً
    }

    const userDoc = await t.get(userRef);
    if (!userDoc.exists) {
      throw new Error('User not found');
    }

    const userData = userDoc.data() || {};
    if (userData.isBanned === true) {
      throw new Error('User is banned');
    }

    const currentCoins = userData.coins || 0;
    const currentNotifications = Array.isArray(userData.notifications)
      ? userData.notifications
      : [];

    t.update(userRef, {
      coins: currentCoins + coinsToAdd,
      lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      notifications: [
        {
          title: '🎉 مكافأة عرض جديدة!',
          body: `تمت إضافة ${coinsToAdd} عملة ذهبية من جدار عروض ${network}`,
          time: 'الآن',
        },
        ...currentNotifications.slice(0, 19),
      ],
    });

    t.set(txRef, {
      uid,
      network,
      coins: coinsToAdd,
      offerId: String(offerId || 'unknown'),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });
}

// 1. مسار UPWALL المحمي بكلمة السر + تشخيص دقيق للرفض
app.get('/upwall-postback', postbackLimiter, async (req, res) => {
  try {
    const expectedPassword = (process.env.UPWALL_POSTBACK_PASSWORD || '').trim();
    const providedPassword = String(
      req.query.password || req.query.secret || req.query.pass || ''
    ).trim();

    if (!isValidSecret(providedPassword, expectedPassword)) {
      console.warn('🚫 Unauthorized UPWALL postback:', {
        ip: req.ip,
        queryKeys: Object.keys(req.query),
        hasPasswordParam: Boolean(req.query.password),
        providedLen: providedPassword.length,
        expectedLen: expectedPassword.length,
        hasSignatureParam: Boolean(req.query.signature || req.query.hash || req.query.sig),
      });
      return res.status(403).send('Forbidden');
    }

    const subId = req.query.subId || req.query.userid;
    const reward = req.query.reward || req.query.user_amount;
    const offerId = req.query.offerId || req.query.offer_id;

    if (!subId || !reward) {
      return res.status(400).send('Missing required parameters');
    }

    await creditUserCoins(subId, reward, 'UPWALL', offerId);
    console.log(`✅ UPWALL: User ${subId} credited with ${reward} coins.`);
    return res.status(200).send('1');
  } catch (error) {
    console.error('❌ UPWALL Postback Error:', error.message);
    return res.status(500).send('0');
  }
});

// 2. مسار AdMantum المحمي بالمفتاح السري
app.get('/admantum-postback', postbackLimiter, async (req, res) => {
  try {
    const expectedSecret = process.env.ADMANTUM_POSTBACK_SECRET;
    const providedSecret = req.query.secret || req.query.password;

    if (!isValidSecret(providedSecret, expectedSecret)) {
      console.warn(`🚫 Unauthorized AdMantum postback attempt from IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }

    const uid = req.query.uid || req.query.subId;
    const amount = req.query.amount || req.query.reward || req.query.virtual_currency;
    const offerId = req.query.offer_id || req.query.of_id || req.query.transaction_id;

    if (!uid || !amount) {
      return res.status(400).send('Missing required parameters');
    }

    await creditUserCoins(uid, amount, 'AdMantum', offerId);
    console.log(`✅ AdMantum: User ${uid} credited with ${amount} coins.`);
    return res.status(200).send('OK');
  } catch (error) {
    console.error('❌ AdMantum Postback Error:', error.message);
    return res.status(500).send('ERROR');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
