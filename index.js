const express = require('express');
const admin = require('firebase-admin');
const app = express();

// تهيئة الاتصال بقاعدة بيانات Firebase باستخدام متغير البيئة في Render
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

app.get('/', (req, res) => {
  res.send('Game Rewards Postback Server is Running Securely!');
});

// دالة موحدة لإضافة العملات بأمان ومنع تكرار العمليات
async function creditUserCoins(uid, amount, network, offerId) {
  const coinsToAdd = Math.floor(Number(amount));
  if (!uid || isNaN(coinsToAdd) || coinsToAdd <= 0) {
    throw new Error('Invalid userId or reward amount');
  }

  const txId = `${network}_${offerId || Date.now()}_${uid}`;
  const txRef = db.collection('completed_offers').doc(txId);
  const userRef = db.collection('users').doc(uid);

  await db.runTransaction(async (t) => {
    const txDoc = await t.get(txRef);
    if (txDoc.exists) {
      return; // العرض محتسب مسبقاً
    }

    const userDoc = await t.get(userRef);
    if (!userDoc.exists) {
      throw new Error('User not found');
    }

    const currentCoins = userDoc.data().coins || 0;
    const currentNotifications = userDoc.data().notifications || [];

    // إضافة العملات وإرسال إشعار للمستخدم داخل التطبيق
    t.update(userRef, {
      coins: currentCoins + coinsToAdd,
      lastUpdate: admin.firestore.FieldValue.serverTimestamp(),
      notifications: [
        {
          title: '🎉 مكافأة عرض جديدة!',
          body: `تمت إضافة ${coinsToAdd} عملة ذهبية من جدار عروض ${network}`,
          time: 'الآن'
        },
        ...currentNotifications.slice(0, 19)
      ]
    });

    t.set(txRef, {
      uid,
      network,
      coins: coinsToAdd,
      offerId: offerId || 'unknown',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  });
}

// 1. مسار استقبال نقاط UPWALL
app.get('/upwall-postback', async (req, res) => {
  try {
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

// 2. مسار استقبال نقاط AdMantum
app.get('/admantum-postback', async (req, res) => {
  try {
    const uid = req.query.uid || req.query.subId;
    const amount = req.query.amount || req.query.reward || req.query.virtual_currency;
    const offerId = req.query.offer_id || req.query.transaction_id;

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
