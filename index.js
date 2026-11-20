const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

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

const MAX_SINGLE_REWARD = 500000;
const AD_REWARD_COINS = 13;
const AD_COOLDOWN_MS = 4 * 60 * 1000; // 4 دقائق بتوقيت السيرفر الحقيقي

// كتالوج الجوائز الرسمي على السيرفر (يمنع تزوير الأسعار من التطبيق)
const REWARDS_CATALOG = {
  google_play_20: { title: 'Google Play $20', cost: 250000, category: 'Google Play', imageUrl: 'assets/images/google_play.jpg' },
  amazon_20:      { title: 'Amazon $20', cost: 250000, category: 'Amazon', imageUrl: 'assets/images/amazon.png' },
  paypal_10:      { title: 'PayPal $10', cost: 130000, category: 'PayPal', imageUrl: 'assets/images/paypal.jpg' },
  usdt_10:        { title: '10 USDT (TRC20)', cost: 150000, category: 'USDT', imageUrl: 'assets/images/usdt.jpg' },
  ff110:          { title: '110 Free Fire Diamonds', cost: 13000, category: 'Free Fire', imageUrl: 'assets/images/freefire.jpg' },
  pubg60:         { title: '60 PUBG Mobile UC', cost: 13000, category: 'PUBG Mobile', imageUrl: 'assets/images/pubg.jpg' },
  pubg325:        { title: '325 PUBG Mobile UC', cost: 65000, category: 'PUBG Mobile', imageUrl: 'assets/images/pubg.jpg' },
  pubg660:        { title: '660 PUBG Mobile UC', cost: 130000, category: 'PUBG Mobile', imageUrl: 'assets/images/pubg.jpg' },
};

// حماية ضد الإغراق
const postbackLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests',
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
});

function isValidSecret(provided, expected) {
  if (!provided || !expected) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function sanitizeDocId(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_');
}

function getTodayUtcKey() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  const d = String(now.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// 🛡️ التحقق من توكن المستخدم المسجّل في Firebase Auth
async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing Authorization token' });
  }
  const idToken = authHeader.slice(7).trim();
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.uid = decoded.uid;
    req.userEmail = decoded.email || 'Unknown';
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.get('/', (req, res) => {
  res.send('Game Rewards Secure Server is Running!');
});

// ==========================================
// 1. مسارات الـ Postback (UPWALL & AdMantum)
// ==========================================
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
      return;
    }

    const userDoc = await t.get(userRef);
    if (!userDoc.exists) throw new Error('User not found');

    const userData = userDoc.data() || {};
    if (userData.isBanned === true) throw new Error('User is banned');

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

app.get('/upwall-postback', postbackLimiter, async (req, res) => {
  try {
    const expectedPassword = (process.env.UPWALL_POSTBACK_PASSWORD || '').trim();
    const providedPassword = String(req.query.password || req.query.secret || '').trim();

    if (!isValidSecret(providedPassword, expectedPassword)) {
      console.warn(`🚫 Unauthorized UPWALL postback attempt from IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }

    const subId = req.query.subId || req.query.userid;
    const reward = req.query.reward || req.query.user_amount;
    const offerId = req.query.offerId || req.query.offer_id;

    if (!subId || !reward) return res.status(400).send('Missing required parameters');

    await creditUserCoins(subId, reward, 'UPWALL', offerId);
    console.log(`✅ UPWALL: User ${subId} credited with ${reward} coins.`);
    return res.status(200).send('1');
  } catch (error) {
    console.error('❌ UPWALL Postback Error:', error.message);
    return res.status(500).send('0');
  }
});

app.get('/admantum-postback', postbackLimiter, async (req, res) => {
  try {
    const expectedSecret = (process.env.ADMANTUM_POSTBACK_SECRET || '').trim();
    const providedSecret = String(req.query.secret || req.query.password || '').trim();

    if (!isValidSecret(providedSecret, expectedSecret)) {
      console.warn(`🚫 Unauthorized AdMantum postback attempt from IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }

    const uid = req.query.uid || req.query.subId;
    const amount = req.query.amount || req.query.reward || req.query.virtual_currency;
    const offerId = req.query.offer_id || req.query.of_id || req.query.transaction_id;

    if (!uid || !amount) return res.status(400).send('Missing required parameters');

    await creditUserCoins(uid, amount, 'AdMantum', offerId);
    console.log(`✅ AdMantum: User ${uid} credited with ${amount} coins.`);
    return res.status(200).send('OK');
  } catch (error) {
    console.error('❌ AdMantum Postback Error:', error.message);
    return res.status(500).send('ERROR');
  }
});

// ==========================================
// 2. مسارات التطبيق المحمية (Server-Side Validation)
// ==========================================

// 🎬 مكافأة الإعلانات (غير محدود • كل 4 دقائق بتوقيت السيرفر • 13 عملة)
app.post('/api/claim-ad', apiLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const today = getTodayUtcKey();
    const userRef = db.collection('users').doc(uid);
    const adRef = userRef.collection('activity').doc('ads');

    const result = await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };

      const userData = userDoc.data() || {};
      if (userData.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const adDoc = await t.get(adRef);
      const adData = adDoc.exists ? (adDoc.data() || {}) : {};

      if (adData.last_ad_time && typeof adData.last_ad_time.toMillis === 'function') {
        const elapsedMs = Date.now() - adData.last_ad_time.toMillis();
        if (elapsedMs < AD_COOLDOWN_MS) {
          const remainingSeconds = Math.ceil((AD_COOLDOWN_MS - elapsedMs) / 1000);
          throw { status: 429, message: 'COOLDOWN', remainingSeconds };
        }
      }

      const prevCount = adData.ads_date === today ? (adData.ads_watched || 0) : 0;
      const newAdsWatched = prevCount + 1;

      t.update(userRef, {
        coins: admin.firestore.FieldValue.increment(AD_REWARD_COINS),
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.set(adRef, {
        ads_watched: newAdsWatched,
        ads_date: today,
        last_ad_time: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

      return { adsWatched: newAdsWatched, reward: AD_REWARD_COINS };
    });

    return res.status(200).json({ success: true, ...result });
  } catch (err) {
    if (err && err.status) {
      return res.status(err.status).json({
        success: false,
        error: err.message,
        remainingSeconds: err.remainingSeconds || 0,
      });
    }
    console.error('❌ /api/claim-ad Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// 🤝 تطبيق كود الإحالة بأمان (+100 للمستخدم، +50 لصاحب الكود)
app.post('/api/apply-referral', apiLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const inputCode = String(req.body.code || '').trim().toUpperCase();
    if (!inputCode) return res.status(400).json({ success: false, error: 'INVALID_CODE' });

    const userRef = db.collection('users').doc(uid);

    await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };

      const userData = userDoc.data() || {};
      if (userData.isBanned === true) throw { status: 403, message: 'USER_BANNED' };
      if (userData.hasUsedReferral === true) throw { status: 400, message: 'ALREADY_USED' };
      if (userData.referralCode === inputCode) throw { status: 400, message: 'SELF_REFERRAL' };

      const refQuery = db.collection('users').where('referralCode', '==', inputCode).limit(1);
      const refSnap = await t.get(refQuery);
      if (refSnap.empty) throw { status: 404, message: 'CODE_NOT_FOUND' };

      const referrerDoc = refSnap.docs[0];
      if (referrerDoc.id === uid) throw { status: 400, message: 'SELF_REFERRAL' };

      t.update(userRef, {
        coins: admin.firestore.FieldValue.increment(100),
        hasUsedReferral: true,
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.update(referrerDoc.ref, {
        coins: admin.firestore.FieldValue.increment(50),
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return res.status(200).json({ success: true, reward: 100 });
  } catch (err) {
    if (err && err.status) {
      return res.status(err.status).json({ success: false, error: err.message });
    }
    console.error('❌ /api/apply-referral Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// 💳 سحب الجوائز عبر السيرفر (يمنع تزوير السعر أو السحب المزدوج)
app.post('/api/redeem', apiLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const rewardId = String(req.body.rewardId || '').trim();
    const accountInfo = String(req.body.accountInfo || '').trim().slice(0, 200);

    const reward = REWARDS_CATALOG[rewardId];
    if (!reward) return res.status(400).json({ success: false, error: 'INVALID_REWARD' });

    const requestId = `REQ-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const userRef = db.collection('users').doc(uid);
    const reqRef = db.collection('redemption_requests').doc(requestId);

    await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };

      const userData = userDoc.data() || {};
      if (userData.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const serverCoins = userData.coins || 0;
      if (serverCoins < reward.cost) throw { status: 400, message: 'INSUFFICIENT_COINS' };

      t.update(userRef, {
        coins: serverCoins - reward.cost,
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.set(reqRef, {
        userId: uid,
        userEmail: req.userEmail,
        rewardId,
        title: reward.title,
        category: reward.category,
        imageUrl: reward.imageUrl,
        cost: reward.cost,
        accountInfo,
        status: 'pending',
        redemptionCode: 'Pending',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    return res.status(200).json({ success: true, requestId });
  } catch (err) {
    if (err && err.status) {
      return res.status(err.status).json({ success: false, error: err.message });
    }
    console.error('❌ /api/redeem Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
