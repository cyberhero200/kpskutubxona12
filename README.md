# Mutolaxona sayti

Bu papka saytning o‘zi. Netlify’ga to‘g‘ri joylansa, kutubxonachi qilgan har bir o‘zgarish hamma qurilmada ko‘rinadi.

```
index.html                      sahifa (o‘quvchilar va kutubxonachi paneli)
netlify/functions/library.mjs   server qismi: umumiy baza va parolni tekshirish
404.html, _redirects            xato sahifasi va yopiq fayllar ro‘yxati
netlify.toml, package.json      Netlify o‘qiydigan sozlamalar
deploy.bat, deploy.sh           terminal orqali joylash (2-usul)
```

## Muhim

Papkani Netlify’ga **sudrab tashlash yetarli emas**. Shunda sahifa ochiladi, lekin Netlify server qismini ishga tushirmaydi: kutubxonachi paneli yopiq turadi va baza umumiy bo‘lmaydi. Quyidagi ikki usuldan biri kerak.

## 1-usul: GitHub orqali (terminal kerak emas)

1. github.com → **New repository** → nom bering (masalan `mutolaxona`) → **Private** → **Create repository**.
2. Ochilgan sahifada **uploading an existing file** havolasini bosing.
3. Shu papka **ichidagi** hamma narsani sudrab tashlang: `index.html`, `404.html`, `_redirects`, `netlify.toml`, `package.json`, `package-lock.json` va `netlify` papkasi. Papkaning o‘zini emas, ichidagilarni. **Commit changes** ni bosing.
4. app.netlify.com → **Add new project** → **Import an existing project** → **GitHub** → shu repozitoriyni tanlang → **Deploy**. Sozlamalarga tegmang.
   Eski saytingiz manzilini saqlamoqchi bo‘lsangiz: o‘sha saytda **Project configuration → Build & deploy → Link repository**.

## 2-usul: terminal orqali

Kompyuterda Node.js bo‘lishi kerak (nodejs.org).

- Windows: `deploy.bat` ni ikki marta bosing.
- macOS / Linux: `sh deploy.sh`

Birinchi marta brauzer ochilib, Netlify’ga kirishni so‘raydi, keyin “Create & configure a new project” ni tanlang.

## Birinchi ishga tushirish

1. Saytni oching, logoni uch marta bosing, parolni kiriting (boshlang‘ich parol: `kitobchi123`).
2. Maktab ro‘yxati (168 o‘quvchi va 49 ustoz) allaqachon ichida: **Kitob berish** bo‘limida ismni yoza boshlasangiz chiqadi. Hech narsa yuklash kerak emas.
3. **Kitoblar ham ichida:** “Umumiy kitoblar” ro‘yxatidagi 1518 nomdagi 7316 nusxa. Kitob berishda nomini yoza boshlang — kirillcha yozsangiz ham, lotincha yozsangiz ham topadi (`matematika` → «Математика») va bo‘sh turgan nusxani o‘zi tanlaydi.
4. Yangi kelgan kitob **Kitoblar → Kitob qo‘shish** orqali kiritiladi. Har bir nusxaning raqami majburiy.
5. **O‘quvchilar** bo‘limida hamma o‘quvchi ro‘yxat bo‘lib turadi: ism ustiga bosilsa, qo‘lidagi kitoblari chiqadi, belgilab bir bosishda qaytarib olish mumkin.

Ro‘yxatlar server qismining ichida turadi (`netlify/functions/library.mjs`), sahifaning o‘zida emas. Yangi odam **Kitobxonlar → Kitobxon qo‘shish** orqali qo‘shiladi.

### O‘quvchilar kitobni o‘zi band qiladi (bron)

1. **Kodlar.** Ro‘yxatdagi 168 o‘quvchi va 49 ustozning kodlari tayyor: ular `mutolaxona-kodlar.pdf` faylida (sinfma-sinf, kesib tarqatiladigan bo‘laklar) va server qismining ichida turadi, shuning uchun sayt joylangan zahoti ishlaydi. Keyin qo‘shilgan odamga kodni panel o‘zi beradi. Bo‘laklarni qayta chiqarish kerak bo‘lsa: **O‘quvchilar** bo‘limida sinfni tanlang va **Kodlarni chop etish** ni bosing.
2. **O‘quvchi kiradi.** Saytda **Kirish** → kitobxon raqami va kod. Brauzer uni 90 kun eslab qoladi. `s146` yoki `146` deb yozsa ham tushunadi.
3. **Band qilish.** Kitob yonidagi **Band qilish** tugmasi. Avval sayt **kitob necha kunga kerakligini** so‘raydi: 7, 14, 21, 30 kun yoki o‘zi yozgan son (1 dan 60 gacha). Kitob javonda bo‘lsa, darhol shu o‘quvchi uchun olib qo‘yiladi va 3 kun kutadi. Hammasi berilgan bo‘lsa, o‘quvchi navbatga yoziladi va kitob qaytishi bilan unga o‘tadi. **Kitoblarim** sahifasida qo‘lidagi kitoblari, bronlari va ballari turadi; so‘ralgan muddatni o‘sha yerda **Muddatni o‘zgartirish** tugmasi bilan almashtirsa bo‘ladi (navbatdagi o‘rni saqlanadi).
4. **Kutubxonachi.** Yangi bron tushganda panelda xabar chiqadi va **Bronlar** bo‘limida (Alt+B) son paydo bo‘ladi. Kitobni bron javoniga qo‘ying. Har bir bron yonida o‘quvchi **so‘ragan muddat** yozilgan. O‘quvchi kelganda **Berish** ni bosing: ism ham, nusxa ham, so‘ralgan kunlar soni ham tayyor turadi, Enter bosilsa bo‘ldi. Muddatni kutubxonachi istagancha o‘zgartira oladi: oxirgi so‘z uniki.
5. **Muddat.** 3 kun ichida olib ketilmasa, bron o‘zi bekor bo‘ladi va kitob navbatdagi kishiga o‘tadi yoki javonga qaytadi.

Qoidalar: bir kishida bir vaqtda ko‘pi bilan 2 ta bron; muddati o‘tgan kitobi bor kishi band qila olmaydi; qo‘lida turgan kitobni qayta band qilib bo‘lmaydi. Raqamlarni o‘zgartirish: `netlify/functions/library.mjs` va `index.html` ichidagi `HOLD = { limit: 2, shelfDays: 3, …, minDays: 1, maxDays: 60 }` (ikkalasida bir xil bo‘lsin). `maxDays` — o‘quvchi so‘rashi mumkin bo‘lgan eng uzun muddat.

Kodni unutgan o‘quvchi: **O‘quvchilar** (yoki **Kitobxonlar**) → ismi → kartaning pastida kodi ko‘rinadi, shuni aytib bersangiz bo‘ldi. O‘zgartirish kerak bo‘lsa: **Kodni o‘zgartirish** bosilib, 6 ta raqamli yangi kod yoziladi (masalan, o‘quvchi o‘zi tanlagani; `111111` yoki `123456` kabi oson kodlar olinmaydi), yoki **Yangi kod** (ikki marta bosiladi) tasodifiy kod beradi. Ikkala holda ham eski kod ishlamay qoladi va o‘quvchi hamma qurilmada qaytadan kiradi.

Kodlar faqat kutubxonachiga ko‘rinadi, sayt ularni hech kimga yubormaydi. Bitta o‘quvchiga 5 marta xato kod yozilsa, keyingi har bir urinish oldidan 2 daqiqa (xatolar ko‘paysa undan ham uzoq) kutiladi. Bloklanib qolgan o‘quvchiga **Yangi kod** bersangiz, darhol kira oladi. **Zaxira fayli ichida kodlar bor**, uni hech kimga bermang.

O‘quvchi band qilayotgan paytda kutubxonachi panelda ishlayversa ham, hech narsa yo‘qolmaydi va hech narsani qaytadan qilish kerak emas: server ikkalasini birlashtiradi. Agar kutubxonachi oxirgi nusxani boshqa odamga berib yuborgan bo‘lsa, band qilgan o‘quvchi navbatda birinchi bo‘lib qoladi.

### Yangi imkoniyatlar (kitobxonlar uchun)

- **Bosh sahifa.** Mehmonga: katta sarlavha, aylanib turadigan besh kitob va kutubxona raqamlarda. Kirgan kitobxonga: salomlashuv, shu oyda o‘qilgani va maqsad, qo‘lidagi kitoblar, **Siz uchun tavsiya** (sinfdoshlari o‘qiyotgan va javonda turgan kitoblar) hamda **Tanlangan kitoblar**.
- **Muddatni uzaytirish.** Qo‘lidagi kitob yonida **Muddatni uzaytirish** → necha kun kerakligini tanlaydi (1–14) → so‘rov kutubxonachiga boradi. Muddati o‘tgan, navbati bor yoki allaqachon 2 marta uzaytirilgan kitob uchun so‘rab bo‘lmaydi.
- **Bildirishnomalar (qo‘ng‘iroqcha).** Kitob olib qo‘yilgani, muddat ertaga tugashi yoki o‘tgani, so‘rovga javob, bron bekor bo‘lgani va sinf topshirig‘i shu yerda ko‘rinadi.
- **Kitoblarim → Sozlamalar.** Oylik o‘qish maqsadi, **kodni o‘zi almashtirish** (hozirgi kod so‘raladi) va sahifa foni naqshi.
- **Reyting.** Davr: hamma vaqt, shu o‘quv yili, shu oy. Kirgan o‘quvchiga o‘z o‘rni ko‘rsatiladi. Kitobxonlarga House yozilgan bo‘lsa, **Houselar** reytingi ham chiqadi.
- **Tillar:** UZ, EN, RU (tepadagi tugmalar).

### Kitob bo‘limlari

- Har bir kitob bitta bo‘limda: O‘zbek adabiyoti, Jahon adabiyoti, Ingliz tilida o‘qish, Bolalar kitoblari, Cambridge va imtihonga tayyorgarlik, Maktab darsliklari, Tillar va lug‘atlar, Tarix va tarjimai hol, Din va ma’naviyat, Davlat, huquq va jamiyat, Fan va shaxsiy rivojlanish, Sport, san’at va musiqa, Boshqa.
- Ro‘yxatdagi 1518 kitob allaqachon bo‘limlarga ajratilgan.
- **O‘quvchilar:** bosh sahifada har bo‘lim uchun alohida plitka; **Kitoblar** sahifasida bo‘lim tugmalari, **Tartib** (A–Z, ko‘p o‘qilgan, javonda ko‘p, avval yangilari) va har kitob yonida bo‘lim belgisi.
- Bo‘limlar sahifaning o‘zida ham bor, shuning uchun server qismi eski bo‘lsa ham ko‘rinadi.
- **Panelda qizil ogohlantirish** chiqsa (“server qismi bu sahifadan eskiroq”), demak Netlify’ga faqat `index.html` yangilangan: butun papkani `netlify` papkasi bilan birga qaytadan joylang.
- **Kutubxonachi:** **Kitoblar** bo‘limida bo‘lim bo‘yicha saralash; kitob ochilganda uning ma’lumotlari oynasida **Bo‘lim** menyusi bor (Saqlash bosilganda o‘zgaradi, Faoliyat jurnaliga yoziladi). Yangi kitob qo‘shishda bo‘lim tanlash majburiy.

### ISBN

- Kitob qo‘shishda, kitob berishdagi “yangi kitob” oynasida va kitobni tahrirlashda **ISBN** maydoni bor (ixtiyoriy). Chiziqcha va bo‘shliq farqi yo‘q; noto‘g‘ri ISBN qabul qilinmaydi.
- **Kitob berishda** ISBN skanerlansa yoki yozilsa, o‘sha nashrning javondagi barcha nusxalari ro‘yxat bo‘lib chiqadi: qo‘ldagi nusxani raqami bo‘yicha tanlang. Ro‘yxatda yo‘q ISBN bo‘lsa, sayt kitob nomi va muallifini internetdan (Open Library, Google Books) topishga harakat qiladi.
- Kitob berishdagi maydon “raqam, nom yoki ISBN” deb so‘raydi; ro‘yxatdagi har bir nusxa yonida nashrning ISBN raqami turadi.
- O‘quvchi bron qilayotganda oynada ISBN va javondagi bo‘sh nusxalar raqamlari ko‘rinadi. Nusxa olib qo‘yilgach xabarda, qo‘ng‘iroqchada, “Mening kitoblarim”da va paneldagi Bronlar bo‘limida aynan shu nusxa raqami va ISBN yoziladi: “Kitob nomi” (nusxa K12-03, ISBN 978…) siz uchun olib qo‘yildi.
- Bir xil nomli, lekin ISBN boshqa bo‘lgan kitob alohida nashr sifatida saqlanadi. Kitoblar, Kitob qaytarish va Kitoblar ro‘yxatida ISBN bo‘yicha qidirish mumkin.

### Houselar

- Maktabning 2026-2027 ro‘yxati bo‘yicha har bir o‘quvchi o‘z house’ida: **Abdurauf Fitrat**, **Abdulla Qodiriy**, **Mahmudxo‘ja Behbudiy**, **Cho‘lpon** (42 + 42 + 41 + 42, sardorlar bilan). Ro‘yxat faqat serverda turadi, sahifa ichida ismlar yo‘q.
- **Reyting**da to‘rtta bo‘lim: O‘quvchilar, **Sinflar** (5–11-sinflar doim ko‘rinadi, har birida “nechtadan nechtasi o‘qiyapti”), **Houselar**, **O‘qituvchilar**.
- **Reyting → Houselar**: to‘rttala house doim ko‘rinadi — ball, o‘qilgan kitoblar, kitobxonlar, o‘quvchilar soni va har bir o‘quvchiga to‘g‘ri keladigan ball. House ustiga bosilsa, shu house kitobxonlari chiqadi. Bosh sahifada **Houselar bellashuvi** (shu o‘quv yili) turadi.
- House’ni o‘zgartirish yoki ro‘yxatda yo‘q o‘quvchiga yozish: panel → **Kitobxonlar → Ma’lumotni tahrirlash → House**. Ro‘yxat bir marta qo‘yiladi, keyin kutubxonachi o‘zgartirgani saqlanadi.

### Mutolaa lentasi

- Kirgan kitobxonning bosh sahifasida, o‘ng ustunda. Postlarni hech kim yozmaydi: kitob **berilganda** va **o‘qib qaytarilganda** sayt o‘zi post chiqaradi (oxirgi 30 kun). Tashqi sun’iy intellekt xizmati ishlatilmaydi, shuning uchun pul ham, kalit ham kerak emas.
- Post tepasida kitobxonning ismi, sinfi va house’i; ustiga bosilsa **profili** ochiladi: ballari, hozir qo‘lidagi va yaqinda o‘qigan kitoblari.
- **Yurakcha** — yoqdi. Rasmga ikki marta bosish ham ishlaydi. Yoqtirish uchun saytga kirgan bo‘lish kerak.
- Lentada ko‘rinishni istamagan kitobxon **Kitoblarim → Sozlamalar → “Kitoblarim mutolaa lentasida ko‘rinsin”** ni o‘chiradi.

### Ballar

- Kitob **olinganda darhol +5 ball**. O‘qib qaytarilsa (kamida bir kun o‘quvchida turgan bo‘lsa) **yana 10**, o‘z vaqtida qaytarilsa **yana 5**. Har bir kitob bir kishi uchun bir marta hisoblanadi.
- Kitob **shikastlangan holda** qaytsa (kutubxonachi qaytarishda holatini “Shikastlangan” deb belgilasa, berilganda esa shikastlanmagan bo‘lsa) **−3 ball**. Jami ball noldan pastga tushmaydi.
- Kutubxonachi panelida kitob berilganda ham, qaytarilganda ham necha ball qo‘shilgani yoki olib tashlangani yozib chiqadi.

### Profil rasmi

- Saytga kirgan kitobxon o‘z rasmini qo‘ya oladi: lenta tepasidagi birinchi doiracha (**Siz**) yoki **Kitoblarim** sahifasi → **Rasm qo‘yish**. Rasm doira shaklida hamma joyda ko‘rinadi: tepada, lentada, profilda, reytingda.
- Rasmlarni **faqat saytga kirganlar** ko‘radi; kirmagan odamga faqat bosh harflar ko‘rinadi.
- Noo‘rin rasmni kutubxonachi olib tashlaydi: panel → **Kitobxonlar** → o‘sha kitobxon → **Rasmni olib tashlash**. Har bir o‘zgarish **Faoliyat** jurnaliga yoziladi.
- Lentada **eng ko‘p yoqqan postlar tepada** turadi, qolganlari tasodifiy tartibda.

### Ustozlar: sinf topshirig‘i

Ustoz o‘z raqami va kodi bilan kirsa, menyuda **Sinf topshirig‘i** paydo bo‘ladi: kitob, muddat (1 hafta, 1 oy yoki sanalar) va sinflar tanlanadi. Shu sinf o‘quvchilari kitobni bosh sahifasida, **Kitoblarim**da va bildirishnomalarda ko‘radi. Ustoz faqat o‘zi bergan topshiriqni olib tashlay oladi.

### Yangi imkoniyatlar (kutubxonachi paneli)

- **Bronlar** bo‘limining tepasida **muddatni uzaytirish so‘rovlari**: **Tasdiqlash** yoki **Rad etish**. Qo‘ng‘iroqchada ham chiqadi.
- **Kitoblar** → kitob nomi bosilsa, tepada kitob ma’lumotlari oynasi ochiladi: **Nomi, Muallif, ISBN, Bo‘lim** — o‘zgartirib **O‘zgarishlarni saqlash** bosiladi (**O‘zgarishlarni bekor qilish** yoki Esc eski holatga qaytaradi). Har bir nusxa yonida **Tahrirlash** tugmasi: nusxa raqami (kitobga yozilgan raqam) va javonni o‘zgartirish; boshqa nusxada bor raqam qabul qilinmaydi. Pastda: **Hafta kitobi / Oy kitobi** (bosh sahifada chiqadi), **Muqova rasmini qo‘shish**, nusxani **Hisobdan chiqarish / Javonga qaytarish**. Hech qachon berilmagan kitobni **o‘chirish** mumkin; berilgan kitob tarixda qoladi.
- **Kitobxonlar** → ism: **Ma’lumotni tahrirlash** (ism, sinf, House), **A’zolikni to‘xtatish / tiklash**, hech narsa olmagan odamni **Ro‘yxatdan o‘chirish**, tarixdagi xato yozuvni **Olib tashlash**, **Saytni shu kitobxon nomidan ko‘rish** (kodsiz, sariq chiziq “Panelga qaytish” bilan).
- **Sinf topshirig‘i** (Alt+A): kutubxonachi ham topshiriq bera oladi va istalganini olib tashlaydi.
- **Faoliyat** (Alt+G): kim nima qilgani, eng yangisi tepada: berish, qaytarish, bron, so‘rovlar, kod almashtirish, tahrirlar. Qidirish va Excel fayli bor.
- **Ma’lumotlar:** **Excel: kitobxonlar, kodlar va o‘qish tarixi**, **Excel: kitoblar va nusxalar**, **Yangi o‘quv yili** (hamma sinf bittaga ko‘tariladi, eng yuqori sinf bitiradi: a’zoligi to‘xtaydi, tarixi qoladi; oldin zaxira faylini saqlang, ortga qaytarib bo‘lmaydi).

Excel fayli ichida kodlar bor, uni ham hech kimga bermang.

### Excel’dan yuklash (import)

- **Ma’lumotlar → Excel yoki CSV dan yuklash**: `.xlsx` (Excel, Google Sheets) yoki `.csv` fayl. Eski `.xls` bo‘lsa, Excel’da **Save As → Excel Workbook (.xlsx)** qilib saqlang.
- **Excel: to‘ldirib yuklash uchun bo‘sh shakl** — uchta varaq: *Odamlar*, *Kitoblar*, *Kimda qaysi kitob*, va yo‘riqnoma varag‘i.
- Varaq turi sarlavhalardan aniqlanadi (o‘zbekcha, ruscha, inglizcha): masalan *F.I.Sh, Sinf, House, Kitob nomi, Muallif, ISBN, Toifa, Inventar raqami, Javon, Berilgan sana, Qaytarish sanasi*. Bir qatorda ham o‘quvchi, ham kitob bo‘lsa — bu “kimda qaysi kitob” varag‘i.
- Yangi odamlarga keyingi raqam (S-…/T-…) va **o‘zining yangi kodi** beriladi: fayldagi kodlar hech qachon ishlatilmaydi. Varaq nomi *O‘qituvchilar* bo‘lsa, o‘qituvchi bo‘lib qo‘shiladi.
- Kitob ISBN yoki nomi bo‘yicha topiladi; yo‘q bo‘lsa yangi kitob qo‘shiladi. Nusxa raqamlari vergul bilan yoziladi yoki faqat soni; soni berilsa, raqamni kutubxona o‘zi beradi (`N12-01`…).
- **Import bosilmaguncha hech narsa o‘zgarmaydi**: oldin xulosa chiqadi — nechta yangi odam, kitob, nusxa, berilgan kitob, nima ro‘yxatda bor va qaysi qatorlar nima uchun o‘tkazib yuborildi. Bir faylni ikki marta yuklash hech narsani ikkilantirmaydi.

### Kitob raqamlari

Ro‘yxatdagi har bir nusxaga `K489-03` ko‘rinishidagi raqam berilgan: `489` — “Umumiy kitoblar” jadvalidagi tartib raqami (т/р), `03` — shu kitobning nechanchi nusxasi. Bu raqamlar kitoblarning o‘ziga yozilmagan, shuning uchun kitob berishda va qaytarishda nomi (yoki o‘quvchi ismi) bo‘yicha ishlash qulay. Jadvalda nomi bir xil yozilgan qatorlar bitta kitob qilib birlashtirilgan; 222-qatorda kitob nomi yo‘q, u kiritilmagan.

### Sayt allaqachon ishlab turgan bo‘lsa

Yangi fayllarni joylasangiz, bazadagi hech narsa o‘chmaydi: berilgan kitoblar, ballar va qo‘lda kiritilgan kitoblar joyida qoladi, ro‘yxatdagi kitoblar ularning yoniga qo‘shiladi. Agar biror kitobni oldin qo‘lda aynan shu nom bilan kiritgan bo‘lsangiz, ro‘yxatdagi nusxalar o‘sha kitobga qo‘shiladi (o‘zingiz kiritgan nusxalar ham qoladi).

Parolni almashtirish: Netlify’da **Project configuration → Environment variables → Add a variable**, kalit `DESK_PASSCODE`, qiymat — yangi parol. Keyin **Deploys → Trigger deploy**.

## Bilib qo‘ying

- **Kim o‘zgartira oladi.** Faqat parolni kiritgan qurilma. Parolni server tekshiradi, sahifa ichida parol ham, uning izi ham yo‘q.
- **Hamma nimani ko‘radi.** Kitoblar, kim nima olgani, band qilgani yoki so‘ragani, sinf topshiriqlari, postlarga bosilgan yurakchalar va o‘sha kishilarning ismi, sinfi hamda house’i. Hali kitob olmaganlar ro‘yxati, kodlar va **Faoliyat jurnali** faqat kutubxonachiga boradi.
- **Yangilanish.** O‘quvchilar sahifasi ochilganda darhol, ochiq turgan bo‘lsa taxminan bir daqiqada yangilanadi.
- **Ikki kutubxonachi bir vaqtda saqlasa**, ikkinchisiga xabar chiqadi va u amalni qaytadan bajaradi. Hech narsa jimgina ustiga yozilmaydi.
- **Internet uzilsa**, panel o‘zgarishni ushlab turadi va qayta urinadi; tepada “Hali saqlanmadi” deb turadi.
- **Zaxira.** **Ma’lumotlar → Zaxira faylini saqlash** hamma narsani faylga yuklab beradi. Server ham har kunning birinchi o‘zgarishidan oldingi holatni 30 kun saqlab turadi (`library` omborida `snap-YYYY-MM-DD`).
- **Noto‘g‘ri parol.** Besh marta xato kiritilgach, o‘sha manzil 30 soniya kutadi.
- Repozitoriy **Private** bo‘lsin: `netlify/functions/library.mjs` ichida o‘quvchilar va ustozlar ro‘yxati, ularning kodlari va kitoblar ro‘yxati bor. `mutolaxona-kodlar.pdf` ni ham faqat tarqatish uchun ishlating. Saytning o‘zidan bu faylni ochib bo‘lmaydi (`_redirects` yopadi).
