const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// ترويسات أمان HTTP قياسية
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(express.json({ limit: '50kb' }));

// معالجة أخطاء JSON التالف بدون كشف تفاصيل السيرفر
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'INVALID_JSON' });
  }
  return next(err);
});

// تهيئة Firebase Admin
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  console.error('❌ FIREBASE_SERVICE_ACCOUNT environment variable is missing!');
  process.exit(1);
}

const db = admin.firestore();

const MAX_SINGLE_REWARD = 500000;
const MIN_OFFER_COINS_FOR_CHALLENGE = 20;      // حد أدنى لقيمة العرض ليُحتسب في تحدي الـ 5 عروض
const AD_REWARD_COINS = 18;
const AD_COOLDOWN_MS = 4 * 60 * 1000;          // 4 دقائق بتوقيت السيرفر
const MAX_DAILY_ADS = 40;                      // حد يومي لحماية حساب AdMob من النقرات المفرطة
const DAILY_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 ساعة للعجلة والبطاقة

// جوائز واحتمالات عجلة الحظ (مجموع الأوزان = 10000)
const WHEEL_PRIZES = [2, 5, 8, 15, 25, 50, 100, 500];
const WHEEL_WEIGHTS = [5000, 3500, 1200, 150, 80, 50, 18, 2];

// جوائز واحتمالات بطاقة المسح (مجموع الأوزان = 1000)
const SCRATCH_PRIZES = [5, 10, 20, 50, 100, 250];
const SCRATCH_WEIGHTS = [400, 300, 150, 100, 40, 10];

// كتالوج الجوائز الرسمي على السيرفر (يمنع تزوير الأسعار ومتوافق مع Google Play)
const REWARDS_CATALOG = {
  google_play_20: { title: 'Google Play $20', cost: 250000, category: 'Google Play', imageUrl: 'assets/images/google_play.jpg', requiresEmail: true },
  amazon_20:      { title: 'Amazon $20', cost: 250000, category: 'Amazon', imageUrl: 'assets/images/amazon.png', requiresEmail: true },
  paypal_10:      { title: 'PayPal $10', cost: 130000, category: 'PayPal', imageUrl: 'assets/images/paypal.jpg', requiresEmail: true },
  ff110:          { title: '110 Free Fire Diamonds', cost: 13000, category: 'Free Fire', imageUrl: 'assets/images/freefire.jpg', requiresEmail: false },
  pubg60:         { title: '60 PUBG Mobile UC', cost: 13000, category: 'PUBG Mobile', imageUrl: 'assets/images/pubg.jpg', requiresEmail: false },
  pubg325:        { title: '325 PUBG Mobile UC', cost: 65000, category: 'PUBG Mobile', imageUrl: 'assets/images/pubg.jpg', requiresEmail: false },
  pubg660:        { title: '660 PUBG Mobile UC', cost: 130000, category: 'PUBG Mobile', imageUrl: 'assets/images/pubg.jpg', requiresEmail: false },
};

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
  message: { success: false, error: 'TOO_MANY_REQUESTS' },
});

function isValidSecret(provided, expected) {
  if (!provided || !expected) return false;
  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function getQueryString(value) {
  if (Array.isArray(value)) return String(value[0] || '').trim();
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function isValidUid(uid) {
  return typeof uid === 'string' && /^[a-zA-Z0-9_-]{6,128}$/.test(uid);
}

function isValidEmail(email) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}

function sanitizeDocId(value, maxLen = 120) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, maxLen);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value).trim().toLowerCase()).digest('hex');
}

function getTodayUtcKey() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  const d = String(now.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function getSecondsUntilUtcMidnight() {
  const now = new Date();
  const nextMidnight = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0, 0, 0
  );
  return Math.max(60, Math.ceil((nextMidnight - now.getTime()) / 1000));
}

function pickWeightedIndex(weights) {
  const total = weights.reduce((a, b) => a + b, 0);
  const r = crypto.randomInt(0, total);
  let cumulative = 0;
  for (let i = 0; i < weights.length; i++) {
    cumulative += weights[i];
    if (r < cumulative) return i;
  }
  return 0;
}

async function deleteRefsInChunks(docRefs, chunkSize = 400) {
  for (let i = 0; i < docRefs.length; i += chunkSize) {
    const batch = db.batch();
    const slice = docRefs.slice(i, i + chunkSize);
    slice.forEach((ref) => batch.delete(ref));
    await batch.commit();
  }
}

// التحقق من توكن Firebase Auth
async function verifyFirebaseToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'MISSING_TOKEN' });
  }
  const idToken = authHeader.slice(7).trim();
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.uid = decoded.uid;
    req.userEmail = (decoded.email || '').trim().toLowerCase();
    return next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'INVALID_TOKEN' });
  }
}

// التحقق من Firebase App Check (يُفعّل من Render عبر ENFORCE_APP_CHECK=true بعد الإنتاج)
async function verifyAppCheck(req, res, next) {
  if (process.env.ENFORCE_APP_CHECK !== 'true') return next();
  const appCheckToken = req.header('X-Firebase-AppCheck');
  if (!appCheckToken) {
    return res.status(401).json({ success: false, error: 'MISSING_APP_CHECK' });
  }
  try {
    await admin.appCheck().verifyToken(appCheckToken);
    return next();
  } catch (err) {
    return res.status(401).json({ success: false, error: 'INVALID_APP_CHECK' });
  }
}

app.get('/', (req, res) => {
  res.status(200).send('Game Rewards Secure Server is Running!');
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// ==========================================
// 0. صفحات سياسة الخصوصية وحذف الحساب (Google Play)
// ==========================================
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support0gamerewards.top@gmail.com';
const APP_NAME = 'Game Rewards';

const LEGAL_PAGE_STYLE = `
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f8f9fb; color: #1f2937; margin: 0; padding: 24px 16px; line-height: 1.7; }
  .card { max-width: 820px; margin: 0 auto; background: #ffffff; border-radius: 14px; padding: 32px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }
  h1 { margin-top: 0; color: #111827; font-size: 26px; border-bottom: 2px solid #d4af37; padding-bottom: 12px; }
  h2 { color: #111827; font-size: 19px; margin-top: 28px; }
  p, li { color: #374151; font-size: 15px; }
  ul, ol { padding-left: 22px; }
  a { color: #b45309; text-decoration: none; font-weight: 600; }
  a:hover { text-decoration: underline; }
  .meta { color: #6b7280; font-size: 14px; margin-bottom: 20px; }
  .box { background: #fffbeb; border-left: 4px solid #d4af37; padding: 14px 18px; border-radius: 6px; margin: 18px 0; }
`;

app.get('/privacy-policy', (req, res) => {
  res.status(200).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Privacy Policy - ${APP_NAME}</title>
  <style>${LEGAL_PAGE_STYLE}</style>
</head>
<body>
  <div class="card">
    <h1>Privacy Policy — ${APP_NAME}</h1>
    <p class="meta">Last updated: November 2026 | Package ID: com.gamerewards.app</p>

    <p>This Privacy Policy explains how <strong>${APP_NAME}</strong> ("we", "our", or "the App") collects, uses, and protects your information when you use our mobile application.</p>

    <h2>1. Information We Collect</h2>
    <ul>
      <li><strong>Account Information:</strong> Email address, username, and unique user ID (UID) created through Firebase Authentication / Google Sign-In.</li>
      <li><strong>Device, Approximate Location &amp; Anti-Fraud Information:</strong> App-scoped Device ID, approximate IP-based region/location, basic security signals (such as VPN, proxy, or root/jailbreak detection), and Google Play Integrity / App Check verification tokens to prevent fraud and multi-account abuse.</li>
      <li><strong>Activity &amp; Rewards Data:</strong> Virtual coin balance, daily check-ins, rewarded video progress, completed offerwall transactions, referral codes, and leaderboard ranking.</li>
      <li><strong>Redemption &amp; Support Details:</strong> Information you voluntarily submit when redeeming digital rewards (such as game Player IDs or delivery email) or opening in-app support tickets.</li>
      <li><strong>Advertising &amp; Diagnostics Data:</strong> Advertising ID (AAID), crash logs, and ad interaction diagnostics collected by our advertising and offerwall partners.</li>
    </ul>

    <h2>2. How We Use Your Information</h2>
    <ul>
      <li>To create and maintain your account and sync your virtual coin balance.</li>
      <li>To credit virtual coins accurately from rewarded videos, daily activities, referrals, and partner offerwalls.</li>
      <li>To process digital reward redemption requests and respond to customer support inquiries.</li>
      <li>To detect, prevent, and block fraudulent activity, automated bots, and policy violations.</li>
    </ul>

    <h2>3. Third-Party Services</h2>
    <p>The App integrates trusted third-party services that may collect information in accordance with their own privacy policies:</p>
    <ul>
      <li><strong>Google Firebase</strong> (Authentication, Cloud Firestore, App Check): <a href="https://firebase.google.com/support/privacy" target="_blank" rel="noopener">Firebase Privacy Policy</a></li>
      <li><strong>Google AdMob</strong> (Rewarded &amp; Banner Advertising): <a href="https://policies.google.com/privacy" target="_blank" rel="noopener">Google Privacy Policy</a></li>
      <li><strong>Partner Offerwalls (UPWALL &amp; AdMantum):</strong> Receive your anonymized App User ID to track completed offers and credit your virtual coin balance via secure server-to-server postbacks.</li>
    </ul>

    <h2>4. Data Security &amp; Retention</h2>
    <p>All communication between the App and our servers is encrypted via HTTPS/TLS. We retain your account data for as long as your account remains active. Certain irreversible hashed anti-fraud records (such as one-way SHA-256 hashes for referral abuse prevention) and completed transaction logs may be retained as needed to protect platform integrity.</p>

    <h2>5. Account &amp; Data Deletion</h2>
    <p>You may permanently delete your account and associated personal data at any time directly inside the App (Settings &rarr; Delete Account) or by following the instructions on our <a href="/delete-account">Account Deletion Page</a>.</p>

    <h2>6. Age Requirement &amp; Children's Privacy</h2>
    <p>${APP_NAME} is intended for users aged <strong>18 and older</strong> and is not directed to children under the age of 13 (or the applicable minimum age in your jurisdiction). We do not knowingly collect personal information from children. If you believe a child has provided us with personal data, please contact us immediately so we can delete it.</p>

    <h2>7. Disclaimer</h2>
    <p>${APP_NAME} is an independent loyalty rewards application and is not affiliated with, sponsored by, or endorsed by Google LLC, Apple Inc., Amazon, PayPal, or the publishers of PUBG Mobile or Free Fire. All trademarks belong to their respective owners.</p>

    <h2>8. Changes to This Policy</h2>
    <p>We may update this Privacy Policy from time to time. Any changes will be posted on this page with an updated revision date.</p>

    <h2>9. Contact Us</h2>
    <p>If you have any questions about this Privacy Policy, please contact us at: <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a></p>
  </div>
</body>
</html>`);
});

app.get('/delete-account', (req, res) => {
  res.status(200).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Delete Account - ${APP_NAME}</title>
  <style>${LEGAL_PAGE_STYLE}</style>
</head>
<body>
  <div class="card">
    <h1>Account &amp; Data Deletion — ${APP_NAME}</h1>
    <p class="meta">App: ${APP_NAME} (com.gamerewards.app)</p>

    <p>Users of <strong>${APP_NAME}</strong> can request permanent deletion of their account and associated personal data at any time using either method below:</p>

    <h2>Option 1: Delete Directly Inside the App (Instant)</h2>
    <ol>
      <li>Open the <strong>${APP_NAME}</strong> app and sign in to your account.</li>
      <li>Go to the <strong>Settings</strong> tab.</li>
      <li>Tap <strong>Delete Account</strong> and confirm the deletion request.</li>
    </ol>

    <h2>Option 2: Request Deletion via Email</h2>
    <div class="box">
      If you cannot access the app, send an email from your registered email address to <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a> with the subject line <strong>"Account Deletion Request - ${APP_NAME}"</strong>. We will verify ownership and process your deletion within <strong>7 business days</strong>.
    </div>

    <h2>What Data Is Deleted</h2>
    <ul>
      <li>Your Firebase Authentication account (email and login credentials).</li>
      <li>Your user profile, username, virtual coin balance, notifications, and activity history.</li>
      <li>In-app support tickets and messages associated with your account.</li>
    </ul>

    <h2>What Data May Be Retained</h2>
    <ul>
      <li>Irreversible anonymized SHA-256 hashes used strictly to prevent referral and bonus abuse.</li>
      <li>Completed reward redemption transaction logs required for accounting and anti-fraud auditing (retained for up to 180 days, then purged).</li>
    </ul>

    <p>For assistance or questions, contact <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a> or view our <a href="/privacy-policy">Privacy Policy</a>.</p>
  </div>
</body>
</html>`);
});

// ==========================================
// 1. مسارات الـ Postback (UPWALL & AdMantum)
// ==========================================
async function creditUserCoins(uid, amount, network, offerId) {
  const cleanUid = String(uid || '').trim();
  const numericAmount = Number(amount);
  const coinsToAdd = Math.floor(numericAmount);
  const cleanOfferId = String(offerId || '').trim();

  if (!isValidUid(cleanUid) || !Number.isFinite(numericAmount) || coinsToAdd <= 0 || coinsToAdd > MAX_SINGLE_REWARD) {
    throw new Error('Invalid userId or reward amount');
  }

  if (!cleanOfferId || cleanOfferId.length > 200) {
    throw new Error('Invalid transaction/offer ID');
  }

  const safeUid = sanitizeDocId(cleanUid, 128);
  const safeOfferId = sanitizeDocId(cleanOfferId, 120);
  const txId = `${network}_${safeOfferId}_${safeUid}`;

  const txRef = db.collection('completed_offers').doc(txId);
  const userRef = db.collection('users').doc(cleanUid);
  const challengeRef = userRef.collection('activity').doc('challenges');

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

    const currentCoins = Number(userData.coins || 0);
    const currentNotifications = Array.isArray(userData.notifications)
      ? userData.notifications
      : [];

    t.update(userRef, {
      coins: currentCoins + coinsToAdd,
      lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      notifications: [
        {
          title: '🎉 مكافأة عرض جديدة!',
          body: `تمت إضافة ${coinsToAdd} عملة افتراضية من جدار عروض ${network}`,
          time: 'الآن',
        },
        ...currentNotifications.slice(0, 19),
      ],
    });

    t.set(txRef, {
      uid: cleanUid,
      network,
      coins: coinsToAdd,
      offerId: cleanOfferId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // احتساب العرض ضمن تحدي الـ 5 عروض فقط إذا كانت قيمته 20 عملة فأكثر
    if (coinsToAdd >= MIN_OFFER_COINS_FOR_CHALLENGE) {
      t.set(challengeRef, {
        monlix_count: admin.firestore.FieldValue.increment(1),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
    }
  });
}

app.get('/upwall-postback', postbackLimiter, async (req, res) => {
  try {
    const expectedPassword = (process.env.UPWALL_POSTBACK_PASSWORD || '').trim();
    const providedPassword = getQueryString(req.query.password || req.query.secret);

    if (!isValidSecret(providedPassword, expectedPassword)) {
      console.warn(`🚫 Unauthorized UPWALL postback attempt from IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }

    const subId = getQueryString(req.query.subId || req.query.userid);
    const reward = getQueryString(req.query.reward || req.query.user_amount);
    const offerId = getQueryString(
      req.query.transId ||
      req.query.transaction_id ||
      req.query.tx_id ||
      req.query.offerId ||
      req.query.offer_id
    );

    if (!subId || !reward || !offerId) {
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

app.get('/admantum-postback', postbackLimiter, async (req, res) => {
  try {
    const expectedSecret = (process.env.ADMANTUM_POSTBACK_SECRET || '').trim();
    const providedSecret = getQueryString(req.query.secret || req.query.password);

    if (!isValidSecret(providedSecret, expectedSecret)) {
      console.warn(`🚫 Unauthorized AdMantum postback attempt from IP: ${req.ip}`);
      return res.status(403).send('Forbidden');
    }

    const uid = getQueryString(req.query.uid || req.query.subId);
    const amount = getQueryString(req.query.amount || req.query.reward || req.query.virtual_currency);
    const offerId = getQueryString(
      req.query.transaction_id ||
      req.query.tx_id ||
      req.query.offer_id ||
      req.query.of_id
    );

    if (!uid || !amount || !offerId) {
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

// ==========================================
// 2. مسار لوحة المتصدرين الآمن (بدون تسريب بيانات خاصة)
// ==========================================
let leaderboardCache = null;
let leaderboardCacheAt = 0;
const LEADERBOARD_CACHE_TTL_MS = 60 * 1000;

app.get('/api/leaderboard', apiLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const now = Date.now();
    if (leaderboardCache && (now - leaderboardCacheAt) < LEADERBOARD_CACHE_TTL_MS) {
      return res.status(200).json({ success: true, leaderboard: leaderboardCache });
    }

    const snap = await db
      .collection('users')
      .where('isBanned', '==', false)
      .orderBy('coins', 'desc')
      .limit(20)
      .get();

    const list = snap.docs.map((doc, idx) => {
      const data = doc.data() || {};
      return {
        rank: idx + 1,
        username: String(data.username || 'Player').slice(0, 30),
        coins: Number(data.coins || 0),
      };
    });

    leaderboardCache = list;
    leaderboardCacheAt = now;
    return res.status(200).json({ success: true, leaderboard: list });
  } catch (err) {
    console.error('❌ /api/leaderboard Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// ==========================================
// 3. مسارات التطبيق المحمية (Server-Side)
// ==========================================

// 🎬 مكافأة الفيديوهات (كل 4 دقائق • 18 عملة • حد أقصى يومي لحماية AdMob)
app.post('/api/claim-ad', apiLimiter, verifyAppCheck, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const today = getTodayUtcKey();
    const userRef = db.collection('users').doc(uid);
    const adRef = userRef.collection('activity').doc('ads');

    const result = await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };
      if (userDoc.data()?.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const adDoc = await t.get(adRef);
      const adData = adDoc.exists ? (adDoc.data() || {}) : {};

      const prevCount = adData.ads_date === today ? Number(adData.ads_watched || 0) : 0;
      if (prevCount >= MAX_DAILY_ADS) {
        throw {
          status: 429,
          message: 'DAILY_LIMIT_REACHED',
          remainingSeconds: getSecondsUntilUtcMidnight(),
        };
      }

      if (adData.last_ad_time && typeof adData.last_ad_time.toMillis === 'function') {
        const elapsedMs = Date.now() - adData.last_ad_time.toMillis();
        if (elapsedMs < AD_COOLDOWN_MS) {
          const remainingSeconds = Math.ceil((AD_COOLDOWN_MS - elapsedMs) / 1000);
          throw { status: 429, message: 'COOLDOWN', remainingSeconds };
        }
      }

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

// 🎡 عجلة الحظ اليومية (كل 24 ساعة • اختيار الجائزة على السيرفر)
app.post('/api/spin-wheel', apiLimiter, verifyAppCheck, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const userRef = db.collection('users').doc(uid);
    const wheelRef = userRef.collection('activity').doc('wheel');

    const result = await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };
      if (userDoc.data()?.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const wheelDoc = await t.get(wheelRef);
      const wheelData = wheelDoc.exists ? (wheelDoc.data() || {}) : {};

      if (wheelData.last_daily_spin_time && typeof wheelData.last_daily_spin_time.toMillis === 'function') {
        const elapsedMs = Date.now() - wheelData.last_daily_spin_time.toMillis();
        if (elapsedMs < DAILY_COOLDOWN_MS) {
          const remainingSeconds = Math.ceil((DAILY_COOLDOWN_MS - elapsedMs) / 1000);
          throw { status: 429, message: 'COOLDOWN', remainingSeconds };
        }
      }

      const prizeIndex = pickWeightedIndex(WHEEL_WEIGHTS);
      const reward = WHEEL_PRIZES[prizeIndex];

      t.update(userRef, {
        coins: admin.firestore.FieldValue.increment(reward),
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.set(wheelRef, {
        last_daily_spin_time: admin.firestore.FieldValue.serverTimestamp(),
        last_reward: reward,
      }, { merge: true });

      return { prizeIndex, reward };
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
    console.error('❌ /api/spin-wheel Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// 🎫 بطاقة الحظ اليومية (كل 24 ساعة • اختيار الجائزة على السيرفر)
app.post('/api/scratch-card', apiLimiter, verifyAppCheck, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const userRef = db.collection('users').doc(uid);
    const scratchRef = userRef.collection('activity').doc('scratch');

    const result = await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };
      if (userDoc.data()?.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const scratchDoc = await t.get(scratchRef);
      const scratchData = scratchDoc.exists ? (scratchDoc.data() || {}) : {};

      if (scratchData.last_daily_scratch_time && typeof scratchData.last_daily_scratch_time.toMillis === 'function') {
        const elapsedMs = Date.now() - scratchData.last_daily_scratch_time.toMillis();
        if (elapsedMs < DAILY_COOLDOWN_MS) {
          const remainingSeconds = Math.ceil((DAILY_COOLDOWN_MS - elapsedMs) / 1000);
          throw { status: 429, message: 'COOLDOWN', remainingSeconds };
        }
      }

      const prizeIndex = pickWeightedIndex(SCRATCH_WEIGHTS);
      const reward = SCRATCH_PRIZES[prizeIndex];

      t.update(userRef, {
        coins: admin.firestore.FieldValue.increment(reward),
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.set(scratchRef, {
        last_daily_scratch_time: admin.firestore.FieldValue.serverTimestamp(),
        last_reward: reward,
      }, { merge: true });

      return { reward };
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
    console.error('❌ /api/scratch-card Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// 🏆 تحديات الألعاب (الدخول اليومي + إتمام 5 عروض)
app.post('/api/claim-challenge', apiLimiter, verifyAppCheck, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    const type = String(body.type || '').trim();
    const today = getTodayUtcKey();

    if (!['daily_login', 'five_offers'].includes(type)) {
      return res.status(400).json({ success: false, error: 'INVALID_CHALLENGE' });
    }

    const userRef = db.collection('users').doc(uid);
    const challengeRef = userRef.collection('activity').doc('challenges');

    const result = await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };
      if (userDoc.data()?.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const chDoc = await t.get(challengeRef);
      const chData = chDoc.exists ? (chDoc.data() || {}) : {};

      let reward = 0;
      const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };

      if (type === 'daily_login') {
        if (chData.last_login_date === today) {
          throw { status: 400, message: 'ALREADY_CLAIMED' };
        }
        reward = 5;
        updates.last_login_date = today;
      } else if (type === 'five_offers') {
        if (chData.five_offers_claimed === true) {
          throw { status: 400, message: 'ALREADY_CLAIMED' };
        }
        if (Number(chData.monlix_count || 0) < 5) {
          throw { status: 400, message: 'NOT_ELIGIBLE' };
        }
        reward = 300;
        updates.five_offers_claimed = true;
      }

      t.update(userRef, {
        coins: admin.firestore.FieldValue.increment(reward),
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.set(challengeRef, updates, { merge: true });
      return { reward };
    });

    return res.status(200).json({ success: true, ...result });
  } catch (err) {
    if (err && err.status) {
      return res.status(err.status).json({ success: false, error: err.message });
    }
    console.error('❌ /api/claim-challenge Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// 🤝 تطبيق كود الإحالة (محمي ضد تكرار حذف الحساب بـ uid + email + deviceId)
app.post('/api/apply-referral', apiLimiter, verifyAppCheck, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    const inputCode = String(body.code || '').trim().toUpperCase();
    if (!inputCode || inputCode.length < 4 || inputCode.length > 32) {
      return res.status(400).json({ success: false, error: 'INVALID_CODE' });
    }

    const userRef = db.collection('users').doc(uid);
    const uidClaimRef = db.collection('referral_claims').doc(`uid_${sanitizeDocId(uid, 128)}`);
    const emailClaimRef = req.userEmail
      ? db.collection('referral_claims').doc(`email_${sha256(req.userEmail)}`)
      : null;

    await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };

      const userData = userDoc.data() || {};
      if (userData.isBanned === true) throw { status: 403, message: 'USER_BANNED' };
      if (userData.hasUsedReferral === true) throw { status: 400, message: 'ALREADY_USED' };
      if (userData.referralCode === inputCode) throw { status: 400, message: 'SELF_REFERRAL' };

      const uidClaimDoc = await t.get(uidClaimRef);
      if (uidClaimDoc.exists) throw { status: 400, message: 'ALREADY_USED' };

      if (emailClaimRef) {
        const emailClaimDoc = await t.get(emailClaimRef);
        if (emailClaimDoc.exists) throw { status: 400, message: 'ALREADY_USED' };
      }

      const rawDeviceId = String(userData.deviceId || '').trim();
      const deviceClaimRef =
        rawDeviceId && rawDeviceId !== 'unknown_device'
          ? db.collection('referral_claims').doc(`dev_${sha256(rawDeviceId)}`)
          : null;

      if (deviceClaimRef) {
        const deviceClaimDoc = await t.get(deviceClaimRef);
        if (deviceClaimDoc.exists) throw { status: 400, message: 'ALREADY_USED' };
      }

      const refQuery = db.collection('users').where('referralCode', '==', inputCode).limit(1);
      const refSnap = await t.get(refQuery);
      if (refSnap.empty) throw { status: 404, message: 'CODE_NOT_FOUND' };

      const referrerDoc = refSnap.docs[0];
      if (referrerDoc.id === uid) throw { status: 400, message: 'SELF_REFERRAL' };
      if (referrerDoc.data()?.isBanned === true) throw { status: 400, message: 'INVALID_CODE' };

      const claimMeta = {
        uid,
        referrerUid: referrerDoc.id,
        code: inputCode,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      t.set(uidClaimRef, claimMeta);
      if (emailClaimRef) t.set(emailClaimRef, claimMeta);
      if (deviceClaimRef) t.set(deviceClaimRef, claimMeta);

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

// 💳 سحب الجوائز عبر السيرفر
app.post('/api/redeem', apiLimiter, verifyAppCheck, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const body = (req.body && typeof req.body === 'object') ? req.body : {};
    const rewardId = String(body.rewardId || '').trim();
    const accountInfo = String(body.accountInfo || '').trim().slice(0, 200);

    const reward = REWARDS_CATALOG[rewardId];
    if (!reward) return res.status(400).json({ success: false, error: 'INVALID_REWARD' });
    if (accountInfo.length < 4) {
      return res.status(400).json({ success: false, error: 'INVALID_ACCOUNT_INFO' });
    }
    if (reward.requiresEmail && !isValidEmail(accountInfo)) {
      return res.status(400).json({ success: false, error: 'INVALID_EMAIL' });
    }

    const requestId = `REQ-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const userRef = db.collection('users').doc(uid);
    const reqRef = db.collection('redemption_requests').doc(requestId);

    await db.runTransaction(async (t) => {
      const userDoc = await t.get(userRef);
      if (!userDoc.exists) throw { status: 404, message: 'USER_NOT_FOUND' };

      const userData = userDoc.data() || {};
      if (userData.isBanned === true) throw { status: 403, message: 'USER_BANNED' };

      const serverCoins = Number(userData.coins || 0);
      if (!Number.isFinite(serverCoins) || serverCoins < reward.cost) {
        throw { status: 400, message: 'INSUFFICIENT_COINS' };
      }

      t.update(userRef, {
        coins: serverCoins - reward.cost,
        lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      });

      t.set(reqRef, {
        userId: uid,
        userEmail: req.userEmail || 'Unknown',
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

// 🗑️ حذف الحساب بالكامل من السيرفر (متوافق مع سياسة Google Play بدون عرقلة App Check)
app.post('/api/delete-account', apiLimiter, verifyFirebaseToken, async (req, res) => {
  try {
    const uid = req.uid;
    const userRef = db.collection('users').doc(uid);
    const userDoc = await userRef.get();

    if (userDoc.exists && userDoc.data()?.isBanned === true) {
      return res.status(403).json({ success: false, error: 'USER_BANNED' });
    }

    // 1. حذف المجموعات الفرعية لنشاط المستخدم وملف المستخدم على دفعات آمنة
    const activitySnap = await userRef.collection('activity').get();
    const userRefsToDelete = [...activitySnap.docs.map((doc) => doc.ref), userRef];
    await deleteRefsInChunks(userRefsToDelete);

    // 2. حذف تذاكر الدعم الفني ورسائلها المرتبطة بالمستخدم على دفعات آمنة
    const ticketsSnap = await db.collection('support_tickets').where('userId', '==', uid).get();
    for (const ticketDoc of ticketsSnap.docs) {
      const msgsSnap = await ticketDoc.ref.collection('messages').get();
      const ticketRefsToDelete = [...msgsSnap.docs.map((m) => m.ref), ticketDoc.ref];
      await deleteRefsInChunks(ticketRefsToDelete);
    }

    // 3. حذف حساب Firebase Auth نهائياً
    try {
      await admin.auth().deleteUser(uid);
    } catch (authErr) {
      if (authErr?.code !== 'auth/user-not-found') throw authErr;
    }

    leaderboardCache = null;

    console.log(`🗑️ Account permanently deleted: ${uid}`);
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('❌ /api/delete-account Error:', err);
    return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
