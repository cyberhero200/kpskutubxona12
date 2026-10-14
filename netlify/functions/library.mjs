// The shared library: one JSON document kept in Netlify Blobs, so every device sees the same books and loans.
//
//   GET  /api/library            anyone         the books, the loans and the people who have borrowed (no e-mails, no card codes)
//        …?z=1                                  the same, packed with gzip (the page unpacks it itself); works on every address below
//   GET  /api/library?since=7    anyone         { unchanged: true } while the library is still at revision 7
//   GET  /api/library?full=1     librarian      everything
//   PUT  /api/library            librarian      { rev, data }  saves, unless another device saved first (409)
//   POST /api/library/login      { passcode }   gives the desk a token for 12 hours
//
// Readers book titles for themselves. Each person has a reader number (S-146) and a personal code the librarian hands out:
//   POST /api/library/reader/login   { no, pin }      gives that reader a token for 90 days
//   POST /api/library/reserve        { bookId, days } reader: book a title (set aside at once, or a place in the queue); days: how long they need it
//   POST /api/library/unreserve      { id }           reader: give the booking up
//   POST /api/library/act            { op, … }        reader: ask for more days (renew / unrenew), set a monthly goal (goal), change
//                                                     their own code (pin), change the days of a booking (holddays), like a post of the reading
//                                                     feed (like) or stay out of the feed (feed); a teacher: set reading for classes (assign / unassign)
//   GET  /api/library/cover?id=12    anyone           the cover picture of a book;  PUT (librarian) stores it, an empty PUT removes it
//   PUT  /api/library/avatar         reader           stores a profile picture (a small JPEG) and answers { v }; the reader then makes it
//                                                     theirs with POST /act { op: 'pic', v }.  PUT ?id=12 with an empty body (librarian) deletes
//   GET  /api/library/avatar?id=12&v=…  whoever knows v   the picture; v cannot be guessed and is handed out only by
//   GET  /api/library/pics           reader, librarian   { rev, pics: { id: v } }: which picture each reader has
// A reader's change is one small step applied here, on the server, and written down in a journal. When the desk then
// saves a copy of the library that is a few such steps behind, the steps are applied to it again instead of being lost,
// so a student booking a book never makes the librarian repeat anything.
//
// The passcode is checked here, on the server. Set it in Netlify: Site configuration > Environment variables > DESK_PASSCODE.
// Without that variable the built-in default below is used (change it with: node set-passcode.mjs "new passcode").
import { getStore } from '@netlify/blobs';
import { createHash, createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';
import { gunzipSync, gzipSync } from 'node:zlib';

const DESK_LOCK = { salt: '64de70e82c825a937282cf0dbcb25307', hash: '6c5eaecb26c305948efdec0024dfcefdd71dab5d796258f12094ad2528dbb4e7', iterations: 150000 };
const TOKEN_HOURS = 12;
const MAX_BYTES = 5_000_000;          // a school library with 7 000 copies is about a fifth of this
const FREE_TRIES = 5;                 // wrong passcodes from one address before it has to wait
const WAIT_SECONDS = 30;              // kept short: a whole school often shares one address, the librarian included
const PUBLIC_CACHE_SECONDS = 10;      // how long Netlify's CDN may reuse the public answer
const READER_DAYS = 90;               // how long a reader stays signed in on a device
const ZONE_HOURS = 5;                 // the school's clock: Asia/Samarkand, UTC+5, no daylight saving
const SERVER_VER = 10;                 // raise with every change the page relies on: the desk warns when the page is newer than this file
const JOURNAL = 1000;                 // how many recent steps are remembered for a desk that saves late (likes are steps too)
const COVER_BYTES = 200_000;          // a cover picture is a small JPEG the page has already cut to size
const AVATAR_BYTES = 80_000;          // a profile picture: 320 x 320, cut by the page
const today = () => new Date(Date.now() + ZONE_HOURS * 3600 * 1000).toISOString().slice(0, 10);

const env = (name) => globalThis.Netlify?.env?.get?.(name) ?? process.env[name] ?? '';
const store = () => getStore({ name: 'library', consistency: 'strong' });
const sha = (text) => createHash('sha256').update(text).digest();
/** An answer as JSON. A big one is packed with gzip when the page asked for that (?z=1): a megabyte becomes about a tenth. */
function json(body, status = 200, headers = {}, zip = false) {
  const text = JSON.stringify(body);
  if (zip && text.length > 4000) return new Response(gzipSync(text), { status, headers: { 'content-type': 'application/octet-stream', 'x-library-gzip': '1', 'cache-control': 'no-store', ...headers } });
  return new Response(text, { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
}

// ---- passcode and tokens
function passcodeOk(given) {
  const set = env('DESK_PASSCODE');
  if (set) return timingSafeEqual(sha(given), sha(set));
  const hash = pbkdf2Sync(given, Buffer.from(DESK_LOCK.salt, 'hex'), DESK_LOCK.iterations, 32, 'sha256');
  return timingSafeEqual(hash, Buffer.from(DESK_LOCK.hash, 'hex'));
}
/** Changing the passcode ends every open desk session, because the passcode is part of what gets signed. */
const passcodeMark = () => sha(env('DESK_PASSCODE') || DESK_LOCK.hash).toString('hex').slice(0, 16);
async function secret(s) {
  let key = await s.get('auth-secret');
  if (!key) { await s.set('auth-secret', randomBytes(32).toString('hex'), { onlyIfNew: true }); key = await s.get('auth-secret'); }
  return key;
}
const sign = (exp, key) => createHmac('sha256', key).update(`desk.${exp}.${passcodeMark()}`).digest('base64url');
async function signedIn(req, s) {
  const m = /^Bearer (\d{10,16})\.([\w-]{20,})$/.exec(req.headers.get('authorization') || '');
  if (!m || Number(m[1]) < Date.now()) return false;
  const want = Buffer.from(sign(m[1], await secret(s))), got = Buffer.from(m[2]);
  return want.length === got.length && timingSafeEqual(want, got);
}

/** Count one try against a limit BEFORE the secret is looked at. The counter is written with compare-and-swap, so a burst of
    parallel guesses is counted one by one and cannot slip past. Returns the seconds to wait, or 0 when this try may go ahead.
    After `free` tries in a row the next ones are let through one per wait; a correct answer or a quiet `window` clears the count. */
async function countTry(s, key, lim, now) {
  for (let i = 0; i < 12; i++) {
    const cur = await s.getWithMetadata(key, { type: 'json' });
    let v = cur && cur.data ? cur.data : null;
    if (!v || now - (v.last || 0) > lim.window) v = { n: 0, until: 0 };
    if (now < v.until) return Math.ceil((v.until - now) / 1000);
    const n = v.n + 1, wait = n >= lim.free ? lim.wait(n) : 0;
    const put = await s.setJSON(key, { n, last: now, until: wait ? now + wait * 1000 : 0 }, cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true });
    if (!put || put.modified !== false) return 0;
  }
  return 3;   // the counter itself is being hammered: ask again in a moment
}
const DESK_TRIES = { free: FREE_TRIES, wait: () => WAIT_SECONDS, window: 15 * 60 * 1000 };
async function login(req, context, s) {
  const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'unknown';
  const key = `tries-${sha(ip).toString('hex').slice(0, 32)}`, now = Date.now();
  let body = null; try { body = await req.json(); } catch (_) { /* not JSON */ }
  const given = body && typeof body.passcode === 'string' ? body.passcode : '';
  const wait = await countTry(s, key, DESK_TRIES, now);
  if (wait) return json({ error: 'wait', wait }, 429);
  if (!given || given.length > 200 || !passcodeOk(given)) return json({ error: 'wrong' }, 401);
  await s.delete(key);
  const exp = now + TOKEN_HOURS * 3600 * 1000;
  return json({ token: `${exp}.${sign(exp, await secret(s))}`, exp });
}

// ---- readers: a reader number plus the personal code. The code lives in the library (people[].pin), only the desk ever receives it.
const noKey = (v) => String(v || '').toUpperCase().replace(/[\s\-_.№#]/g, '').replace(/С/g, 'S').replace(/Т/g, 'T');   // Cyrillic С and Т count as S and T
const trimZeros = (k) => k.replace(/^([A-Z]*)0+(?=\d)/, '$1');
/** Everyone the typed number can mean: "S-146", "s146", "146" (and "5" can be S-005 or T-05; the code decides). */
function readersFor(d, typed) {
  const k = trimZeros(noKey(typed));
  if (!k || k.length > 12) return [];
  return d.people.filter((p) => { const mine = trimZeros(noKey(p.no)); return !!mine && (mine === k || (/^\d+$/.test(k) && mine.replace(/^[A-Z]+/, '') === k)); });
}
/** Changing a reader's code ends that reader's sessions, because the code is part of what gets signed. */
const readerSign = (p, exp, key) => createHmac('sha256', key).update(`reader.${p.id}.${exp}.${sha(String(p.pin)).toString('hex').slice(0, 16)}`).digest('base64url');
function readerOf(req, d, key) {
  const m = /^Reader (\d{1,9})\.(\d{10,16})\.([\w-]{20,})$/.exec(req.headers.get('authorization') || '');
  if (!m || Number(m[2]) < Date.now()) return null;
  const p = d.people.find((x) => x.id === Number(m[1]));
  if (!p || !p.pin || p.active === false) return null;
  const want = Buffer.from(readerSign(p, m[2], key)), got = Buffer.from(m[3]);
  return want.length === got.length && timingSafeEqual(want, got) ? p : null;
}
/** Tries are counted per person (so one reader's code cannot be guessed: five quick tries, then one every two minutes, then slower
    and slower) and, loosely, per address (so nobody can go through the whole school; loose, because a school shares one address).
    The count belongs to the code as well as the person: a new code from the librarian starts it afresh. */
const LIMITS = {
  who: { free: 5, wait: (n) => (n < 10 ? 120 : n < 20 ? 900 : 3600), window: 24 * 3600 * 1000 },
  ip: { free: 300, wait: () => 30, window: 10 * 60 * 1000 },
};
const whoKey = (p) => `rwho-${p.id}-${sha(String(p.pin)).toString('hex').slice(0, 12)}`;
async function readerLogin(req, context, s) {
  let body = null; try { body = await req.json(); } catch (_) { /* not JSON */ }
  const typed = noKey(body && typeof body.no === 'string' ? body.no : ''), pin = (body && typeof body.pin === 'string' ? body.pin : '').replace(/\D/g, '');
  if (!typed || typed.length > 12 || !pin || pin.length > 12) return json({ error: 'wrong' }, 401);
  const ip = context?.ip || req.headers.get('x-nf-client-connection-ip') || 'unknown', now = Date.now();
  const busy = await countTry(s, `rip-${sha(ip).toString('hex').slice(0, 32)}`, LIMITS.ip, now);
  if (busy) return json({ error: 'wait', wait: busy }, 429);
  const d = withStart(await s.get('doc', { type: 'json' })).data;
  const readers = readersFor(d, typed).filter((p) => p.pin && p.active !== false), given = sha(pin);
  let hit = null, wait = 0, checked = 0;
  if (!readers.length) wait = await countTry(s, `rwho-x-${sha(trimZeros(typed)).toString('hex').slice(0, 32)}`, LIMITS.who, now);   // a number nobody has is counted too
  for (const p of readers) {
    const w = await countTry(s, whoKey(p), LIMITS.who, now);
    if (w) { wait = Math.max(wait, w); continue; }
    checked++;
    if (timingSafeEqual(sha(String(p.pin)), given)) { hit = p; break; }
  }
  if (!hit) return wait && !checked ? json({ error: 'wait', wait }, 429) : json({ error: 'wrong' }, 401);
  await s.delete(whoKey(hit));
  const exp = now + READER_DAYS * 24 * 3600 * 1000;
  return json({ token: `${hit.id}.${exp}.${readerSign(hit, exp, await secret(s))}`, exp, me: { id: hit.id, no: hit.no, kind: hit.kind, enName: hit.enName, uzName: hit.uzName, cls: hit.cls, house: hit.house } });
}

// ---- the school's own list: students by grade and teachers
// It is the library's starting state, so the desk has everyone from the first minute and nothing has to be loaded by hand.
// build-netlify.py copies the list here from the page source. Visitors never receive it: only people who have borrowed
// are sent to readers, and _redirects keeps this file itself from being downloaded.
// The school's books follow, from the library's own list. They are part of the starting state as well, and a library
// that was saved before the books were added gets them on its next read (see mergeCatalog).
/*<roster>*/
const ROSTER = {
  classes: [
    ['5', ["Allaberganova Xusniya", "Amonboyev Fazliddin", "Azimov Ulug‘bek", "Bekpo‘latov A’zamjon", "Durdibayev Temur", "Egamberdiyev Shohjahon", "Jumanazarov Shohjahon", "Karimbayev Asrorbek", "Kutlimuratov Muhammadmurod", "Mametov Bobur", "Matchonova Laziza", "Matkarimov Azizbek", "Maxsudov Shixnazar", "Muxiddinov Bahodirjon", "Otaboyev Aslbek", "Palvannazirov Javohirbek", "Po‘latova Aziza", "Rahmanov Nurmuhammad", "Saparbayeva Umida", "Shamuratov Sadulla", "Soburov Sarvarbek", "Sultonbayev Mehrojbek", "Sultonov Abror", "Xolmurodov Suroj"]],
    ['6', ["Abdullayev Bunyodbek", "Axmedov Rajabboy", "Axmedov Sardorbek", "Baxramov Musobek", "Begnazarov Abdulaziz", "Egamberganov Artur", "Ermatov Kamronbek", "Farxodov Abrorbek", "Ismailov Iskandar", "Janibekov Islombek", "Kamilbayeva Dilnura", "Kurbanbayev Asilbek", "Kurbobayev Masharip", "Nuroddinova Yulduz", "Nurullayev Muhammadali", "Ollaberganov Abduakbar", "Ollaberganova Shahnoza", "Otaxonova Munira", "Rajabboyev Hojiakbar", "Raxmatullayeva Shohina", "Saidnazarova Dilfuza", "Suvanova Hamida", "Tuxtabayev Davud", "Umarjonov Dovud"]],
    ['7', ["Abdullayev Azizbek", "Ataxonov Akbarjon", "Atayeva Barno", "Azimov Boburbek", "Baxtiyarov Abdulaziz", "Baxtiyarov Elyor", "Baxtiyorov Abdulaziz", "Jumaboyev Nurali", "Jumanazarov E’zozbek", "Maqsudbekova Nilufar", "Matyusupov Nurbek", "Navruzov Nursulton", "Otabekov Musobek", "Qo‘chqarov Bilolbek", "Rajabbayev Musobek", "Raximov Rizobek", "Sapayev Mustafo", "Shanazarov Behruzbek", "Shomurotov Mirjalol", "Xamdamov Suhrobbek", "Xursandov Feruzbek", "Yangiboyeva Dilshoda", "Yo‘ldashov Jonibek", "Yusupboyeva Rahimajon"]],
    ['8', ["Abdullayev Jaloliddin", "Alimbayev Salohiddin", "Baxramov Umrbek", "Baxtiyorova Zilola", "Boxodirov Behruzbek", "Ibadullayeva Zuhraxon", "Jumaboyev Baxtiyor", "Komilov Zafar", "Maksudov Diyorbek", "Maxsudov Polvonbek", "Mirzakarimov Nodirbek", "Niyozmetov Azizbek", "Odilbekov Madaminbek", "Otabekova Shaydo", "O‘ktamboyev Mirjahon", "Ravshanov Asilbek", "Rustamov Behruzbek", "Sadikov Hasanboy", "Saparboyev Sardorbek", "Sobirov Sobirjon", "Sultannazarov Akbar", "Urinbayeva Adiba", "Xudayarov Doniyor", "Xusinov Axrorbek"]],
    ['9', ["Atayev Zufar", "Azamatov Alibek", "Bahodirov Behruzbek", "Bakdurdiyev Laziz", "Dushamboev Shahjahon", "Dushamov Ulug‘bek", "Ergashboyev Yunusbek", "Ergashboyeva Rayhonoy", "Erkinov Muhammadamin", "Kuryazov Javoxir", "Masharipov Bekzod", "Masharipova Mushtariy", "Matchanov Javohir", "Polvanazirova Nodiraxon", "Rajabbayev Ibrat", "Rajabboyeva Malika", "Raximov Ne’matjon", "Salayev Rasulbek", "Sardorov Kamronbek", "Shamilov Shohruh", "Sultanbayev Akmal", "Tuxtabayev Deniz", "Ulug‘bekov Mironshox", "Ulug‘bekova Mohira"]],
    ['10', ["Aminboeva Ruxshona", "Bahodirova Mushtariybonu", "Baxtiyarov Oybek", "Bekmuratov Akbar", "Davronbekov Bardiboy", "Gul’matov Behruzbek", "Ikromov Muhammadjon", "Islomboev Bunyobek", "Karimboyev Olloshukur", "Komiljonova Shahrizoda", "Ko‘palov Shohjahon", "Matkarimov Odilbek", "Otaboyev Islombek", "Otaxonov Asadbek", "Rustamov Nurazizbek", "Saitjanov Abbos", "Sa’dullayev Hasanboy", "Sa’dullayev Husanboy", "Shukurlayev Samadjon", "Sobirova Guli", "Sotimbaev Ibratbek", "Taxirjanov Abdulaziz", "Yangiboyeva Shahzoda", "Yo‘ldoshev Abdulloh"]],
    ['11', ["Allaberganov Xudoybergan", "Arslonbekov Dilmurod", "Azadov Sanjarbek", "Baxramov Kamronbek", "Bobojonov O‘tkirbek", "Duschanova Nigina", "Iskandarov Shohruhbek", "Komilov Javohir", "Matmuratov Amirhon", "Nazarov Rasulbek", "Ozimboyev Abror", "Ozodov Munisbek", "O‘rozmatov Mirjalol", "Radjapboyev Murodbek", "Rajabboyev Shahriyor", "Rajabov Sahriyor", "Sadullayev Asadulloh", "Sadullayev Jasurbek", "Shoxnazarova Gulsanam", "Ulug‘bekova Dinora", "Xajiyev Xajiboy", "Xamroyeva Nilufar", "Xojayeva Shaxloxon", "Yangiboeva Farangiz"]],
  ],
  teachers: ["Adolat Alimjanovna", "Adolat Allaberganova", "Atamurad Matnazarov", "Bunyod Khalikberdiev", "Clement Odera", "Dilnoza Atadjanova", "Donovan Solomons", "Farhod Allaberganov", "Farook Ali", "Farrux Xakimov", "Gavin Haschek", "Hamza Otayev", "Iqbola Ortiqova", "Ivy Mogano", "Ixtiyor Xudarganov", "Jacinta Muriu", "Kakai Wasula", "Laila Botirova", "Lobar Ismayilova", "Madina Masharipova", "Marxabo Davlatova", "Maryanne Deguzman", "Muyassar Maxsudovna", "Muyassar Palvanova", "Nargiza Khamraeva", "Nilufar Babajanova", "Nodirbek Xusinov", "Otabek Ganjayev", "Oybek Abdullayev", "Paul Wangui", "Ramazon Ruzimov", "Rashid Rajapov", "Reyno Abasolo", "Sarvar Sharipov", "Sattorbek Yo‘ldoshev", "Sevara Norbaeva", "Shahlo Ibragimova", "Shirin Bayjanova", "Shohruh Madrimov", "Shohsura Shavkatova", "Shoira Gulamova", "Shujaat Khan", "Silondiwe Mathebula", "Soxiba Babanazarova", "Stephan Safari", "Vaisbek Atanazarov", "Yullrich Cloete", "Zafar Ismoilov", "Zilola Raximberganova"],
  // Houses 2026-2027, from the school's own list: every student of a house, its captain included.
  houses: [
    ["Abdurauf Fitrat", ["Abdullayev Bunyodbek", "Allaberganova Xusniya", "Aminboeva Ruxshona", "Ataxonov Akbarjon", "Baxramov Kamronbek", "Baxramov Umrbek", "Baxtiyarov Elyor", "Baxtiyorova Zilola", "Boxodirov Behruzbek", "Durdibayev Temur", "Egamberganov Artur", "Jumanazarov E’zozbek", "Karimbayev Asrorbek", "Karimboyev Olloshukur", "Kurbobayev Masharip", "Kutlimuratov Muhammadmurod", "Masharipov Bekzod", "Matmuratov Amirhon", "Odilbekov Madaminbek", "Ollaberganov Abduakbar", "Ollaberganova Shahnoza", "Otaboyev Aslbek", "Otaxonov Asadbek", "Ozodov Munisbek", "Polvanazirova Nodiraxon", "Rajabbayev Ibrat", "Rajabbayev Musobek", "Rustamov Nurazizbek", "Sadullayev Asadulloh", "Saparboyev Sardorbek", "Shamilov Shohruh", "Shamuratov Sadulla", "Shomurotov Mirjalol", "Sultanbayev Akmal", "Sultannazarov Akbar", "Taxirjanov Abdulaziz", "Tuxtabayev Davud", "Tuxtabayev Deniz", "Xajiyev Xajiboy", "Xamroyeva Nilufar", "Yo‘ldoshev Abdulloh", "Yusupboyeva Rahimajon"]],
    ["Abdulla Qodiriy", ["Alimbayev Salohiddin", "Amonboyev Fazliddin", "Atayeva Barno", "Axmedov Rajabboy", "Davronbekov Bardiboy", "Dushamov Ulug‘bek", "Ergashboyev Yunusbek", "Ergashboyeva Rayhonoy", "Ermatov Kamronbek", "Farxodov Abrorbek", "Ibadullayeva Zuhraxon", "Iskandarov Shohruhbek", "Matkarimov Odilbek", "Maxsudov Polvonbek", "Maxsudov Shixnazar", "Mirzakarimov Nodirbek", "Nuroddinova Yulduz", "Nurullayev Muhammadali", "Otaxonova Munira", "Ozimboyev Abror", "O‘rozmatov Mirjalol", "Palvannazirov Javohirbek", "Qo‘chqarov Bilolbek", "Radjapboyev Murodbek", "Rahmanov Nurmuhammad", "Rajabboyeva Malika", "Ravshanov Asilbek", "Raximov Ne’matjon", "Raximov Rizobek", "Sadikov Hasanboy", "Salayev Rasulbek", "Saparbayeva Umida", "Sapayev Mustafo", "Sa’dullayev Hasanboy", "Shoxnazarova Gulsanam", "Shukurlayev Samadjon", "Sobirova Guli", "Sotimbaev Ibratbek", "Sultonov Abror", "Ulug‘bekova Dinora", "Xursandov Feruzbek", "Yo‘ldashov Jonibek"]],
    ["Mahmudxo‘ja Behbudiy", ["Abdullayev Azizbek", "Allaberganov Xudoybergan", "Axmedov Sardorbek", "Azadov Sanjarbek", "Azamatov Alibek", "Azimov Ulug‘bek", "Bahodirov Behruzbek", "Bahodirova Mushtariybonu", "Bakdurdiyev Laziz", "Baxtiyarov Abdulaziz", "Baxtiyarov Oybek", "Baxtiyorov Abdulaziz", "Begnazarov Abdulaziz", "Bekpo‘latov A’zamjon", "Duschanova Nigina", "Dushamboev Shahjahon", "Ikromov Muhammadjon", "Jumaboyev Baxtiyor", "Jumaboyev Nurali", "Kamilbayeva Dilnura", "Komilov Javohir", "Komilov Zafar", "Ko‘palov Shohjahon", "Kurbanbayev Asilbek", "Maksudov Diyorbek", "Masharipova Mushtariy", "Matchonova Laziza", "Matkarimov Azizbek", "Muxiddinov Bahodirjon", "Niyozmetov Azizbek", "Otabekova Shaydo", "Otaboyev Islombek", "Rajabboyev Hojiakbar", "Rustamov Behruzbek", "Saitjanov Abbos", "Sardorov Kamronbek", "Sultonbayev Mehrojbek", "Suvanova Hamida", "Xamdamov Suhrobbek", "Xojayeva Shaxloxon", "Yangiboyeva Dilshoda"]],
    ["Cho‘lpon", ["Abdullayev Jaloliddin", "Atayev Zufar", "Azimov Boburbek", "Baxramov Musobek", "Bekmuratov Akbar", "Bobojonov O‘tkirbek", "Egamberdiyev Shohjahon", "Erkinov Muhammadamin", "Gul’matov Behruzbek", "Islomboev Bunyobek", "Ismailov Iskandar", "Janibekov Islombek", "Jumanazarov Shohjahon", "Komiljonova Shahrizoda", "Kuryazov Javoxir", "Mametov Bobur", "Maqsudbekova Nilufar", "Matchanov Javohir", "Matyusupov Nurbek", "Navruzov Nursulton", "Nazarov Rasulbek", "Otabekov Musobek", "O‘ktamboyev Mirjahon", "Po‘latova Aziza", "Rajabboyev Shahriyor", "Rajabov Sahriyor", "Raxmatullayeva Shohina", "Sadullayev Jasurbek", "Saidnazarova Dilfuza", "Sa’dullayev Husanboy", "Shanazarov Behruzbek", "Sobirov Sobirjon", "Soburov Sarvarbek", "Ulug‘bekov Mironshox", "Ulug‘bekova Mohira", "Umarjonov Dovud", "Urinbayeva Adiba", "Xolmurodov Suroj", "Xudayarov Doniyor", "Xusinov Axrorbek", "Yangiboeva Farangiz", "Yangiboyeva Shahzoda"]],
  ],
};
/*</roster>*/
/*<catalog>*/
const CATALOG = [
  ["Рус адабиёти дурдоналари \"Пушкин\", 91-жилд (лотин)",[[1,1]],"world"],
  ["М.Н. Аникина. А дан Я гача Рус тилини поғонама поғона урганамиз",[[2,5]],"lang"],
  ["Зарифа Ускинова. Замонавий рус тили граматикаси",[[3,5]],"lang"],
  ["Жорж Оруэлл:1984",[[4,5]],"world"],
  ["Чампо отли илон",[[5,5]],"kids"],
  ["Уч сайёхнинг сафари",[[6,5]],"world"],
  ["Уткир зехинлилар",[[7,7]],"science"],
  ["И дольше века длится день",[[8,2]],"world"],
  ["Шаркона тарбия 3",[[9,1],[73,1]],"science"],
  ["Юлдузлар мангу ёнади",[[10,2]],"uzlit"],
  ["Cambridge IGCSE level Computer Science Second Edition Algoritms, Programming and Logic(2years) 9781398318472",[[11,50]],"cambridge"],
  ["Девоний Ниёзий",[[12,2]],"uzlit"],
  ["Киме оламига саёхат",[[13,2]],"science"],
  ["9781107665996Camdridge chekpoint Mathematics Practice book 8",[[14,23]],"cambridge"],
  ["Узбек халк эртаклари Акл ва бойлик",[[15,3]],"kids"],
  ["Алгебрадан масаллар туплами",[[16,9]],"school"],
  ["Ун беш ёшли капитан",[[17,4]],"world"],
  ["Кашкир улиган тун",[[18,4]],"uzlit"],
  ["Сунги ижро",[[19,7]],"uzlit"],
  ["Oxford Bookworms Library Stage 4 Bestseller Pack (10)=30",[[20,3]],"english"],
  ["\"Товуш сояси\" 53 жилд",[[21,1]],"world"],
  ["Cambridge International AS &",[[22,28]],"cambridge"],
  ["Шавкат Мирзиёев \"Танқидий тахлил, қатий тартиб интизом ва шахсий жавобгарлик - ҳар бир раҳбар фаолиятининг кундалик қоидаси бўлиши керак\"",[[23,3]],"society"],
  ["Ижод боғидан гулдаста",[[24,12]],"uzlit"],
  ["Математикадан қизиқарли масалалар",[[25,5]],"science"],
  ["Чингиз Айтматов Қасандра Тамғаси",[[26,5]],"world"],
  ["Кулга тушмас касоскор",[[27,5]],"world"],
  ["Суз чамани",[[28,9]],"uzlit"],
  ["Жалолиддин Румий",[[29,1]],"world"],
  ["Вафо маликаси ёхуд Амир темур ва Улжай ока кисмати",[[30,2]],"uzlit"],
  ["Топишмоклар М.Ахмедов",[[31,8]],"kids"],
  ["Янги таҳрирдаги Ўзбекистон Республикасининг Конституциясининг матни А4 форматдаги кирил тилида",[[32,4]],"society"],
  ["Янги Ўзбекистон тараққиёт стратегияси (кирил)",[[33,1]],"society"],
  ["Complete Chemistry for Cambridge IGCSE® & O Level",[[34,56]],"cambridge"],
  ["Адолат манзили",[[35,5]],"uzlit"],
  ["Бемор А.Каххор",[[36,5]],"uzlit"],
  ["Бола подшодир",[[37,5],[114,5]],"science"],
  ["Фарзандар китобди",[[38,5]],"science"],
  ["Ака ука",[[39,4]],"uzlit"],
  ["Окчорлок",[[40,5]],"kids"],
  ["Тулкичанинг саргузаштлари",[[41,4]],"kids"],
  ["Пиноккионииг саргузаштлари",[[42,2]],"kids"],
  ["Рус адабиёти дурдоналари \"Тирилиш\",18- жилд(узб/лотин),",[[43,2]],"world"],
  ["Ўткир Ҳошимов \"Икки эшик орасида\"",[[44,5]],"uzlit"],
  ["\"Odob axloq kitobi\" Beruniy",[[45,10]],"science"],
  ["\"Aljabrning tug‘ilishi\" M.Osim",[[46,5]],"science"],
  ["Қушлар дунёсига саёхат",[[47,1]],"science"],
  ["Севги шундай навбахорки Э.Вохидов",[[48,1]],"uzlit"],
  ["Озор халк эртаклари",[[49,6]],"kids"],
  ["Учар гилам каттик",[[50,2]],"kids"],
  ["Олтин сочли йигит",[[51,1],[242,1]],"kids"],
  ["Урушнинг сунги курбони",[[52,5]],"uzlit"],
  ["Шумтакалар",[[53,7]],"kids"],
  ["Кеча ва кундуз",[[54,5],[191,5]],"uzlit"],
  ["Осий банда О.Ёкубов",[[55,1],[906,2]],"uzlit"],
  ["ШОХ",[[56,1]],"uzlit"],
  ["Миллий тараккиёт йулимизни катъият билан давом эттириб,",[[57,2]],"society"],
  ["Сказки старого дуба,Сказки и рассказы о животных",[[58,1]],"kids"],
  ["Инглизча ашулалар,шеърлар, маколлар, тез айтишлар",[[59,2]],"lang"],
  ["И.С.Тургенев \"Отцы и дети\" (переиздание)",[[60,2]],"world"],
  ["Окшом эртаклари16",[[61,10]],"kids"],
  ["Сехрли бог",[[62,5]],"kids"],
  ["Ун икки йуловчи",[[63,5]],"world"],
  ["Авлиё Сергей",[[64,15],[569,1]],"world"],
  ["Аловиддининг сехрли чироги",[[65,6]],"kids"],
  ["Олтин тарвуз",[[66,4]],"kids"],
  ["Хрестоматия литературных произведения 1",[[67,3]],"school"],
  ["Cambridge Checkpoint Science Teacher’s Resource 9",[[68,4]],"cambridge"],
  ["Спортда илмий тадқиқотлар",[[69,3]],"arts"],
  ["\"Тинч Дон\"(4 китобли роман.3-китоб) 44-жилд( лотин)",[[70,1]],"world"],
  ["Бемор",[[71,10]],"uzlit"],
  ["Маугли",[[72,9]],"kids"],
  ["\"Tilla uzuk \"O.Yoqubov",[[74,5]],"uzlit"],
  ["Амур Темур даврдошлари",[[75,2]],"history"],
  ["Касос алангасида",[[76,1]],"uzlit"],
  ["Гулливернинг саёхатлари",[[77,10]],"world"],
  ["Cambridge Checkpoint Mathematics Challenge Workbook 9",[[78,28]],"cambridge"],
  ["Mechanics for Cambridge International AS & A Level: Print & Online Student Book Pack",[[79,28]],"cambridge"],
  ["Ingliz grammatikasi",[[80,5]],"lang"],
  ["Усмон Гозихон 1-2 китоб",[[81,7]],"history"],
  ["Рустамхон",[[82,4]],"uzlit"],
  ["Роберт Кийосаки",[[83,6]],"science"],
  ["Ернештейин ва иблисвачча",[[84,7]],"world"],
  ["Маленькие дикари",[[85,1]],"world"],
  ["Роял казиноси",[[86,2]],"world"],
  ["Кадимги Рим ва Атилла",[[87,2],[198,1]],"history"],
  ["Геометриядан масалалар туплами",[[88,8]],"school"],
  ["Изтироб",[[89,4]],"uzlit"],
  ["Папугай золотом кувшине",[[90,1]],"kids"],
  ["Жахон халк эртаклари каттик 1",[[91,2]],"kids"],
  ["Мехробдан чаён",[[92,5],[699,2]],"uzlit"],
  ["Эй чехраси тобоним Мукумий, Фуркат",[[93,1]],"uzlit"],
  ["Глобаллашув: миллатни асраш маъсулияти",[[94,1]],"society"],
  ["Узбек география фани фидоийлари",[[95,2]],"history"],
  ["Инглизча-узбекча-русча лугат (кайта нашр)",[[96,2]],"lang"],
  ["Узбек халк эртаклари Мукбил тош отар",[[97,3]],"kids"],
  ["8-sinf Kimyo",[[98,9]],"school"],
  ["Cambridge Checkpoint Mathematics Practice book 7",[[99,28]],"cambridge"],
  ["Cambridge IGCSE Biology Workbook",[[100,28]],"cambridge"],
  ["Cambridge International AS & A Level Global Perspectives & Research Digital Teacher’s Resource",[[101,4]],"cambridge"],
  ["Бокс",[[102,3]],"arts"],
  ["Золотая поэзия Серебряного века",[[103,2]],"world"],
  ["Андиша ва гурур",[[104,1]],"world"],
  ["Курд халк эртаклари",[[105,5]],"kids"],
  ["Шарк хикоя ва ривоятлари",[[106,1]],"world"],
  ["Шеърлар болалар учун Зарчечак",[[107,1]],"kids"],
  ["Mir Alisher Navoiy",[[108,2]],"uzlit"],
  ["Набор кодексов (Бюджет кодекси)",[[109,1]],"society"],
  ["9781108948937 Cambridge IGCSE™ Chemistry Digital Teacher’s Resource Access Card",[[110,2]],"cambridge"],
  ["Cambridge Checkpoint Mathematics Challenge Workbook 8",[[111,24]],"cambridge"],
  ["Бедор тун томчилари",[[112,5]],"uzlit"],
  ["Ёш билимлилар энциклопедияси",[[113,20]],"lang"],
  ["18 га кирмаган ким бор",[[115,1]],"uzlit"],
  ["Эртаклар яхшиликка етаклар Сусамбил",[[116,1]],"kids"],
  ["Эрону Турон назмул-жавохири",[[117,2]],"world"],
  ["9781107697874 Cambridge Checkpoint Mathematics Coursebook 8",[[118,28]],"cambridge"],
  ["\"Ko‘xna dunyo\" O.Yoqubov",[[119,5]],"uzlit"],
  ["\"Charli va shakaod fabrikasi\"R.Dal,E.Xogard",[[120,10]],"world"],
  ["Аждодларимиз фожияси",[[121,2]],"history"],
  ["Вой онажон Т.Малик",[[122,2]],"uzlit"],
  ["Сказки под подушки 2",[[123,1]],"kids"],
  ["Уруш ва тинчлик",[[124,3]],"world"],
  ["Ватан мехри",[[125,1]],"uzlit"],
  ["Cambridge IGCSE™ Combined and Co-ordinated Sciences Digital Teacher’s Resource Код IBSN 9781009311373",[[126,2]],"cambridge"],
  ["Жахон тарихи энг янги давр 1918-1945 йил, 3 кием",[[127,2]],"school"],
  ["ХИМИЯ для поступающих в вузов (янги натр)",[[128,2]],"school"],
  ["\"Чол,киз ва офтаб\" 86 жилд",[[129,1]],"world"],
  ["Шайтанат 4,5",[[130,1]],"uzlit"],
  ["Cambridge AS and A level Chemistry Practical Teacher’s Guide",[[131,28]],"cambridge"],
  ["Михаил Булгаков Уста ва Маргарита",[[132,5]],"world"],
  ["Луғат инглизча-ўзбекча, ўзбекчағ-инглизча Замиржон Бутаев",[[133,3]],"lang"],
  ["Пауло Коэлё: Алиф",[[134,5]],"world"],
  ["Внеклассное чтение 3",[[135,5]],"school"],
  ["Шаркона тарбия 1",[[136,1],[200,1]],"science"],
  ["Послание Президента Республики Узбекистан Мирзиёева Олий Мажлису (рус)",[[137,4]],"society"],
  ["Шум боланинг набиралари",[[138,6],[501,10]],"uzlit"],
  ["9781108796750 Cambridge International AS & A Level Physics Digital Teacher’s Resource Access Card",[[139,2]],"cambridge"],
  ["Шайтонваччанинг найранглари 1",[[140,2]],"kids"],
  ["Болалар учуй шеърлар Зарчечак",[[141,3]],"kids"],
  ["Хикматлар шодаси",[[142,1]],"uzlit"],
  ["Кора либосли келинчак",[[143,1]],"uzlit"],
  ["Сарвкомат Дилбарим",[[144,2]],"uzlit"],
  ["Турсуной Содикова 4",[[145,2]],"uzlit"],
  ["Турсуной Содикова 3",[[146,2]],"uzlit"],
  ["Cambridge IGCSE™ Physics Digital Teacher’s Resource Access Card",[[147,2],[1539,1]],"cambridge"],
  ["Уч юз олтмиш турт кун",[[148,6]],"uzlit"],
  ["Пахлавон тошлар",[[149,4]],"kids"],
  ["Дюмчахон",[[150,5],[355,6]],"kids"],
  ["Қалдирғоч",[[151,3]],"kids"],
  ["Безовталикдан кандай кутулиб яшаш мумкин",[[152,1]],"science"],
  ["Синфдан ташқари ўқиш китоби 4",[[153,1]],"school"],
  ["Cambridge Checkpoint Science Coursebook 9",[[154,28]],"cambridge"],
  ["Cambridge IGCSE Physics practical Workbook",[[155,48]],"cambridge"],
  ["\"Тинч Дон\"( торт китобли роман.1-китоб)42-жилд(лотин)",[[156,1]],"world"],
  ["\"Тулқин ва тош\"58-жилд(узбек/лотин)",[[157,1]],"world"],
  ["\"Oxirat\"T.Malik",[[158,5]],"uzlit"],
  ["\"Asrni qaritgan kun\" Ch.Aytmatov",[[159,5]],"world"],
  ["\"Oltin vodiydan shabadalar\"Oybek",[[160,5]],"uzlit"],
  ["\"Уруш ва тинчлик\"3-4 китоб 15-жилд",[[161,1]],"world"],
  ["Рус адабиёти дурдоналари \"Анна Каренина\",(1-китоб),16- жилд(узб/лотин).",[[162,2]],"world"],
  ["Гарри Поттер ва афсонавий тош",[[163,2]],"world"],
  ["Астрономия ва коинот энсиқлопедия",[[164,5]],"science"],
  ["Сунбил билан Гул",[[165,1],[647,1]],"kids"],
  ["Жаннати одамлар",[[166,2]],"uzlit"],
  ["Суфи Оллохёр",[[167,2]],"religion"],
  ["Рохибнинг кайгуси",[[168,6]],"world"],
  ["Аёзи чузилган бахор",[[169,3]],"uzlit"],
  ["Харитага тушмаган жой",[[170,5],[253,5]],"uzlit"],
  ["Новые приключения Мюнхаузена и Ходжи Насреддина",[[171,2]],"kids"],
  ["Туккиз хокон салтанати",[[172,1]],"history"],
  ["Том Соернинг бошидан кечирганлари",[[173,2]],"world"],
  ["Амур Темур гарбиё европа адиблари нигохида",[[174,2]],"history"],
  ["Хикоялар ва ибратли сузлар",[[175,3]],"uzlit"],
  ["Мехригиёх (узбек халк эртаклари) Эргаш Очилов",[[176,1]],"kids"],
  ["Лайлакларим менинг",[[177,5]],"uzlit"],
  ["Бой ота камбагал ота",[[178,3]],"science"],
  ["Суикасд",[[179,3],[307,3]],"world"],
  ["Хаётнинг беш тортиги",[[180,5]],"science"],
  ["111 ватандош ьалломаларимиз",[[181,2]],"history"],
  ["Фаришта ва ялмоги",[[182,8]],"kids"],
  ["Топишмоклар загадки",[[183,5]],"kids"],
  ["Cambridge Lower Secondary Global Perspectives Stage 8 Teacher’s Book",[[184,4]],"cambridge"],
  ["\"Болалаик\"33-жилд( лотин)",[[185,1]],"world"],
  ["\"Руйхатларда йуқ эди номи/Тонглар сокин эди бу ерда\"39-жилд(лотин)",[[186,1]],"world"],
  ["Сайланма М.Юсуф",[[187,1],[332,2]],"uzlit"],
  ["А.Навоий асарларида фалаккиёт сирлари",[[188,1]],"uzlit"],
  ["O‘zbeklar.O`.Hoshimov",[[189,5]],"uzlit"],
  ["Савдогар ва карокчилар",[[190,3]],"kids"],
  ["Руский язик А-Я",[[192,4]],"lang"],
  ["Тирик колиш буюрилган",[[193,4]],"uzlit"],
  ["Уруш аёллар иши эмас",[[194,10]],"world"],
  ["Узбек халк; эртаклари Мукбил тош отар",[[195,3]],"kids"],
  ["Узбек халқ эртаклари Эгри билан Тўғри",[[196,3]],"kids"],
  ["Олимжоннинг саргузаштлари",[[197,5],[350,3]],"kids"],
  ["Сиз нотик булмокчимисиз?",[[199,2]],"science"],
  ["Уммон остидаги жавохир",[[201,4]],"world"],
  ["Чамадон",[[202,7]],"world"],
  ["Лаънати махлук",[[203,2]],"world"],
  ["Кучадан келган бола",[[204,2]],"world"],
  ["Бог куча болалари",[[205,4]],"uzlit"],
  ["Сказки дядюшки Римуса",[[206,1]],"kids"],
  ["Ака -ука грим эртаклари Миттивойлар совгаси",[[207,1]],"kids"],
  ["Узбек халк эртаклари Нон ва тилла",[[208,3],[817,3]],"kids"],
  ["International AS & A Level Computer Science Revision Guide",[[209,28]],"cambridge"],
  ["Cambridge IGCSE Physics Coursebook",[[210,28]],"cambridge"],
  ["Саид Ахмад \"Жимжитлик\"",[[211,5]],"uzlit"],
  ["\"Devoni lug‘otit turk\"M.Qoshg‘ariy",[[212,5]],"lang"],
  ["Кайдасан болалигим",[[213,8]],"uzlit"],
  ["Вақт бу пул",[[214,1]],"science"],
  ["Летучий корабль",[[215,1]],"kids"],
  ["Синфдан ташкари укишЗ",[[216,2]],"school"],
  ["Болага китоб беринг",[[217,4]],"science"],
  ["Танхо кайик",[[218,3]],"world"],
  ["Бадият бош мезон",[[219,4]],"uzlit"],
  ["Юракнинг бир чети",[[220,5]],"uzlit"],
  ["Бировга кулма зинхор",[[221,4]],"kids"],
  ["Махтумкули (тарих ва шахе) (Узбекский)",[[223,2]],"history"],
  ["Кичкина Янко",[[224,2],[674,1]],"world"],
  ["Янги Ўзбекистон тараққиёт стратегияси асосида демократик ислоҳотлар йўлини қатъий давом эттирамиз (лотин)",[[225,1]],"society"],
  ["Кухна дунё",[[226,4],[912,1]],"uzlit"],
  ["Буюк келажагимизни мард ва олийжаноб халкимиз билан бирга курамиз",[[227,2]],"society"],
  ["Мари -Анри Бейл Стендал \"Қизил ва қора\"",[[228,3]],"world"],
  ["Cambridge International AS and A Chemistry practical Workbook",[[229,4]],"cambridge"],
  ["Луғат инглизча-ўзбекча, ўзбекчағ-инглизча 70.000",[[230,5]],"lang"],
  ["Куринмас одам",[[231,2],[619,8]],"world"],
  ["Хоразмнинг сунги маликаси",[[232,2]],"uzlit"],
  ["Инглиз тили феъл замонлари (машк ва тест жавоблари) (К.Иногамова)",[[233,4]],"lang"],
  ["Хотиралар тулкини Г.Хожиев",[[234,2]],"uzlit"],
  ["Масаллар",[[235,2]],"kids"],
  ["Cambridge Lower Secondary Computing Student’s Book 9 Код ISBN: 9781398369825",[[236,14]],"cambridge"],
  ["Cambridge IGCSE and O Level Business Studies Авторы: Karen Borrington, Peter Stimpson (29 Mar 2018) Код ISBN: 9781510421233",[[237,24]],"cambridge"],
  ["Янги Ўзбекистонда эркин ва фаровон яшайлик (кирил)",[[238,1]],"society"],
  ["\"Жаноб Головлёвлар\"28-жилд(лотин)",[[239,1]],"world"],
  ["Уйга кайтиш",[[240,7]],"uzlit"],
  ["Севги киссалари",[[241,8]],"uzlit"],
  ["Шайтонваччанинг найранглари 2",[[243,2]],"kids"],
  ["100 билан юзлашиб юринг",[[244,2]],"science"],
  ["Чархпалак Тохир Малик",[[245,2]],"uzlit"],
  ["Cambridge Checkpoint Mathematics Coursebook 7",[[246,28]],"cambridge"],
  ["Сунги сабок",[[247,7]],"world"],
  ["Пеналопанинг кундалиги",[[248,7]],"world"],
  ["100 Мумтоз файласуф",[[249,1]],"science"],
  ["Бобур. Юлдузли тунлар",[[250,1]],"uzlit"],
  ["STARTING Engilish, 2-синф (укитувчилар учун укув кулланма), 1-китоб (К.Инагамова)",[[251,2]],"school"],
  ["Математика С.Бурхонов",[[252,3]],"school"],
  ["Cambridge Lower Secondary Computing Student’s 7 Код ISBN: 9781398369320",[[254,14]],"cambridge"],
  ["7-sinf adabiyot",[[255,6]],"school"],
  ["Харкимки вафо килса",[[256,5]],"uzlit"],
  ["Шаркнинг энг буюк хукмдори",[[257,2],[830,7]],"history"],
  ["8-sinf geometriya",[[258,5]],"school"],
  ["Complete Physics for Cambridge – third edition IGCSE workbook",[[259,1]],"cambridge"],
  ["Cambridge International AS and A Level Chemistry Revision Guide",[[260,28]],"cambridge"],
  ["Кашфиёт ва ихтиролар энсиқлопедия",[[261,5]],"lang"],
  ["\"Gulliverning sayohatlari\"J.Svift",[[262,10]],"world"],
  ["So‘z chamani.Zulfiya",[[263,5]],"uzlit"],
  ["Шухрат васвасаси",[[264,1]],"world"],
  ["Узбек тили имло луғати",[[265,5]],"lang"],
  ["Педагогика энциклопедияси III",[[266,2]],"lang"],
  ["Момо ер кушиги",[[267,4]],"uzlit"],
  ["Самалётдаги угрилик",[[268,7]],"kids"],
  ["Нидо",[[269,5],[492,4]],"uzlit"],
  ["Сказки и рассказы о животных (переиздание)",[[270,2]],"kids"],
  ["Гарри Поттер ва зоти паст шахзода 6",[[271,2]],"world"],
  ["\"Urush va Tinchlik \" 1-2 kitob",[[272,5]],"world"],
  ["Сунги нидо (узб/кирил)",[[273,2]],"uzlit"],
  ["Суз саньати сузлиги Е.Исоков",[[274,2]],"lang"],
  ["Туркман халк донишмандлиги (янги нашр)",[[275,1]],"world"],
  ["Бировнинг хакки",[[276,2]],"uzlit"],
  ["Янгиланаётган Конституция номли инфографик тўплам",[[277,2]],"society"],
  ["Олтин балик",[[278,5]],"kids"],
  ["Қиёмат Ч. Айтматов",[[279,2]],"world"],
  ["Cambridge Lower Secondary Global Perspectives Stage 7 Teacher’s Book",[[280,4]],"cambridge"],
  ["Cambridge Checkpoint Science Workbook 8",[[281,28]],"cambridge"],
  ["\"Денгиздан эсган шабада\"39-жилд(лотин)",[[282,1]],"world"],
  ["Севги изтироблари",[[283,6]],"world"],
  ["Тазарру",[[284,4]],"uzlit"],
  ["Математика",[[285,4]],"school"],
  ["Иван Ильични улими",[[286,5]],"world"],
  ["Марияга пул керак",[[287,8]],"world"],
  ["Жахон халк эртаклари",[[288,4]],"kids"],
  ["Болалар учун макол топишмок шеърлар",[[289,1]],"kids"],
  ["Эртаклар яхшиликка етаклар Куёш ернинг пахлавони",[[290,1]],"kids"],
  ["Юзма-юз Ч.Айтматов",[[291,1]],"world"],
  ["Complete Chemistry for Cambridge IGCSE® & O Level Workbook",[[292,28]],"cambridge"],
  ["Kurash",[[293,2]],"arts"],
  ["Саъдий \"Бўстон\"",[[294,1]],"world"],
  ["Шохнома",[[295,5]],"world"],
  ["А.Орипов \"Эверес ва Уммон\"",[[296,1]],"uzlit"],
  ["Саид Ахмад \"Уфқ\"",[[297,5]],"uzlit"],
  ["\"Jamila\" Ch.Aytmatov",[[298,5]],"world"],
  ["Попугай золотом кувшине",[[299,1]],"kids"],
  ["Детство",[[300,3]],"world"],
  ["Cambridge Checkpiont Lower Secondary Computing 9 Student’s Book Boost eBook 9781398371187",[[301,14]],"cambridge"],
  ["Халкимизнинг розилиги бизнинг фаолиятимизга берилган энг",[[302,3]],"society"],
  ["9781108903417 Cambridge International AS & A Level Economics Coursebook with Digital Access Book Оригинальный учебник",[[303,52]],"cambridge"],
  ["Кунчикар мамлакат хикоялари",[[304,20]],"world"],
  ["9-sinf Rus tili",[[305,5]],"school"],
  ["Cambridge Checkpoint Mathematics Challenge Workbook 7",[[306,28]],"cambridge"],
  ["Аёлга касида",[[308,3]],"uzlit"],
  ["Хушқадам",[[309,2]],"uzlit"],
  ["Енгил атлетика",[[310,3]],"arts"],
  ["Рус адабиёти дурдоналари \"Анна Каренина\",(2-китоб),17- жилд(узб/лотин).",[[311,2]],"world"],
  ["Zamonaviy rus grammatikasi",[[312,5]],"lang"],
  ["Сехргар билан бола",[[313,1]],"kids"],
  ["Вавилонлик энг бой одам",[[314,6]],"science"],
  ["Улуг онанинг жанозаси",[[315,4]],"world"],
  ["Зулмат ичра нур",[[316,5]],"uzlit"],
  ["Хаётнинг беш тортиги Марк Твен",[[317,1]],"world"],
  ["Тавба",[[318,2]],"religion"],
  ["Дунёнинг ишлари лотин",[[319,1]],"uzlit"],
  ["Уч мушкетер",[[320,2]],"world"],
  ["Бир куни Зулфия опа билан",[[321,1]],"uzlit"],
  ["Иблис девори Тохир Малик",[[322,2]],"uzlit"],
  ["Шерлок Хомснинг сунги саргузаштлари",[[323,1]],"world"],
  ["Ажал билан юзма юз",[[324,3]],"uzlit"],
  ["Complete Chemistry for Cambridge IGCSE® & O Level Teacher Resource Pack",[[325,4]],"cambridge"],
  ["Cambridge Checkpoint Science Coursebook 7",[[326,4]],"cambridge"],
  ["\"Кунгилли учрашув\"46-жилд(лотин)",[[327,1]],"world"],
  ["\"Кур мусикачи\"31-жилд",[[328,1]],"world"],
  ["Ёлғончи ёр",[[329,1]],"uzlit"],
  ["Марья краса долгая коса",[[330,1]],"kids"],
  ["Икки кисса",[[331,2]],"uzlit"],
  ["Янги Ўзбекистонда эркин ва фаровон яшайлик (лотин)",[[333,1]],"society"],
  ["9781108921220 Cambridge International AS & A Level Business Coursebook with Digital Access Book Оригинальный учебниктф",[[334,52]],"cambridge"],
  ["9781108947497 Cambridge IGCSE Biology practical Workbook",[[335,56]],"cambridge"],
  ["Буюк юрт алломалари",[[336,1]],"history"],
  ["Асирга татигулик кун",[[337,2]],"uzlit"],
  ["Фасохат мулкининг сохибкирони (Ботирхон Акрамов)",[[338,2]],"uzlit"],
  ["Кайсар кизнинг куйилиши",[[339,2],[579,2],[942,5]],"world"],
  ["Кулаётган тоглар (Мангу кайлик)",[[340,1]],"world"],
  ["Буюк 75",[[341,6]],"history"],
  ["Рус адабиёти дурдоналари \"Кора кузлар\",10- китоб,(узб/лотин).",[[342,2]],"world"],
  ["Probability & Statistics 1 for Cambridge International AS & A Level: Print & Online Student Book Pack",[[343,28]],"cambridge"],
  ["Pure Mathematics 2 & 3 for Cambridge International AS & A Level: Print & Online Student Book Pack",[[344,28]],"cambridge"],
  ["Ўткир Ҳошимов \"Дафтар ҳошиясидаги битиклар\"",[[345,5]],"uzlit"],
  ["Кор куйинидаги лола",[[346,6]],"uzlit"],
  ["Г.Гулом асарли",[[347,3]],"uzlit"],
  ["Бир кунлик куналга",[[348,3]],"uzlit"],
  ["Туй арафасида",[[349,2]],"uzlit"],
  ["Хожимурод",[[351,5],[725,1],[938,2]],"world"],
  ["Истиклол калдиргочлари",[[352,4]],"history"],
  ["Телба келиннинг кундалиги",[[353,2]],"uzlit"],
  ["Узбек адабиётшунослигининг икки маликаси",[[354,2]],"uzlit"],
  ["Бунда булбул китоб укийди",[[356,2]],"kids"],
  ["7-sinf rus tili",[[357,6]],"school"],
  ["Уч ип йигирувчи",[[358,6]],"kids"],
  ["Робин Шарма энг сара асарлари",[[359,12]],"science"],
  ["Хурмача полвон",[[360,5]],"kids"],
  ["\"Bozatov Ilhomlari\" китоб",[[361,20]],"uzlit"],
  ["\"Василий Тюркин\"",[[362,1]],"world"],
  ["Спорт ва миллий ўйинлар (футбол)",[[363,3]],"arts"],
  ["\"Қора одам\"(узбек/лотин)36-жилд",[[364,1]],"world"],
  ["\"Хаёт бустони\" 70-жилд",[[365,1]],"world"],
  ["Соглом фарзанд-оила кувончи (лотин)",[[366,6]],"science"],
  ["Бахтини йукотган гузал Лайло",[[367,2]],"uzlit"],
  ["Хажвий хикоялар",[[368,2],[401,1]],"uzlit"],
  ["Узбек халк эртаклари Дехкон ва Айик",[[369,3],[473,3]],"kids"],
  ["Турсуной Содикова 5",[[370,2]],"uzlit"],
  ["Марк Твен",[[371,6]],"world"],
  ["Поднимите свой финансовый IQ",[[372,5]],"science"],
  ["Италян халк эртаклари",[[373,5]],"kids"],
  ["Хамелон",[[374,4]],"world"],
  ["Отца и дети",[[375,5]],"world"],
  ["Кувгиндаги кекса кирол",[[376,7]],"world"],
  ["Яширин хазина",[[377,5]],"kids"],
  ["Узбек халк эртаклари",[[378,5]],"kids"],
  ["Узбек халк; эртаклари Мохир уста",[[379,3]],"kids"],
  ["Қор маликаси",[[380,5]],"kids"],
  ["Икки эшик ораси",[[381,1],[744,2]],"uzlit"],
  ["Қора шахзода",[[382,1]],"world"],
  ["Pemberton Mathematics for Cambridge IGCSE 3rd edition student’s book",[[383,56]],"cambridge"],
  ["Она бурининг хийласи",[[384,2]],"kids"],
  ["Жахон тарихидаги сулола ва давлатлар 3-китоб",[[385,3]],"history"],
  ["2023 йил - Инсонга эътибор ва сифатли таълим йили китоби",[[386,2]],"society"],
  ["Кошинга теккизма каламни Амирий",[[387,4]],"uzlit"],
  ["Oxford Bookworms Library Stage 3 Bestseller Pack (10)/ Оксфорд библиотека книжного червя Уровень 3 комплект",[[388,3]],"english"],
  ["Cambridge Checkpoint Science Teacher’s Resource 8",[[389,4]],"cambridge"],
  ["Бадиий гимнастика спорт педагогик махоратини ошириш",[[390,3]],"arts"],
  ["Probability & Statistics 2 for Cambridge International AS & A Level: Print & Online Student Book Pack",[[391,28]],"cambridge"],
  ["Гарри Поттер ва ажал тухфалари 7",[[392,2]],"world"],
  ["Чаёнлар сукмоги",[[393,3]],"uzlit"],
  ["Дерза орти манзаралари",[[394,5]],"uzlit"],
  ["Кайгу гули",[[395,6]],"uzlit"],
  ["Адабиёт муаллими",[[396,2]],"uzlit"],
  ["Атиргул угриси",[[397,7]],"uzlit"],
  ["Бури угли",[[398,5]],"uzlit"],
  ["Нурли тилаклар",[[399,10]],"uzlit"],
  ["Эрк",[[400,5],[686,3]],"uzlit"],
  ["Жим Рон Энг сара асарлари",[[402,1]],"science"],
  ["Тохир Малик \"Шайтанат\" 4.5",[[403,1]],"uzlit"],
  ["Ер сайёраси энсиқлопедия",[[404,5]],"lang"],
  ["\"Me’mor \" Mirmuhsin",[[405,10]],"uzlit"],
  ["Намоз полвон",[[406,5]],"uzlit"],
  ["Рубаиий",[[407,2]],"world"],
  ["Абдулла Кодирий кашфиёти",[[408,2]],"uzlit"],
  ["Тулкинчанинг саргузатшлари (эртак-кисса, кайта нашр)",[[409,2]],"kids"],
  ["Хумоюн ва Акбар",[[410,1]],"uzlit"],
  ["Мажоз ва хакикат",[[411,2]],"religion"],
  ["Узбек халк эртаклари Эгри билан тугри",[[412,3]],"kids"],
  ["Оила энциклопедияси",[[413,1]],"lang"],
  ["Султон Жалолиддин Мангу берди",[[414,2]],"history"],
  ["Энгилмас жангчи",[[415,5]],"uzlit"],
  ["Икрорнома",[[416,6],[788,5]],"uzlit"],
  ["Тинчликни улуглаймиз",[[417,7]],"society"],
  ["Феруза",[[418,7]],"uzlit"],
  ["Сказки о билом",[[419,2]],"kids"],
  ["Дилкушо такрорлар",[[420,1]],"uzlit"],
  ["Cambridge Checkpoint Mathematics Teacher’s Resource 8",[[421,4]],"cambridge"],
  ["Cambridge IGCSE Biology Coursebook",[[422,28]],"cambridge"],
  ["Футбол",[[423,3]],"arts"],
  ["Саид Ахмад \"Қора кўз мажнун\"",[[424,5]],"uzlit"],
  ["Роберт Киосаки Бой ота,камбағал ота",[[425,5]],"science"],
  ["Дахшат А.Каххор",[[426,5]],"uzlit"],
  ["Сунги раматик",[[427,4]],"uzlit"],
  ["Навоий сухбатлари",[[428,2],[889,1]],"uzlit"],
  ["Жодугар ва малика",[[429,3]],"kids"],
  ["Кайдасан болалилигим X Тухтабоев",[[430,2]],"uzlit"],
  ["Янги таҳрирдаги Ўзбекистон Республикасининг Конституциясининг матни А4 форматдаги лотин тилида",[[431,15]],"society"],
  ["Cambridge IGCSE Combined and Co-ordinated Sciences Coursebook with Digital Acce",[[432,24]],"cambridge"],
  ["Сказки под подушки 1",[[433,1]],"kids"],
  ["Одамийлик киссаси",[[434,5]],"uzlit"],
  ["Етти юлдуз",[[435,4]],"uzlit"],
  ["Ғалаба боғи фалсафаси",[[436,8]],"history"],
  ["Жарима батальени",[[437,1]],"world"],
  ["Амур Темур сулоласи",[[438,2]],"history"],
  ["Дафтар хошиясидаги битиклар",[[439,6]],"uzlit"],
  ["Робин Шарма:Ўлсанг,ким йиғлайди",[[440,5]],"science"],
  ["Малколм Гладуэлл: Зукколар ва ландовурлар",[[441,5]],"science"],
  ["Йигит шундай булса Э.Малик",[[442,2]],"science"],
  ["Халк огзаки ижоди Рустам",[[443,2]],"uzlit"],
  ["Болалик хотираларим",[[444,2]],"uzlit"],
  ["А.Чехов Семиз ва орик",[[445,3],[1004,1]],"world"],
  ["Эрк саодати",[[446,3]],"uzlit"],
  ["Эртаклар яхшиликка етаклар Қирқ ёлгон",[[447,1]],"kids"],
  ["Уткир зехнлилар китоби4",[[448,2]],"science"],
  ["Янги Ўзбекистон тараққиёт стратегияси асосида демократик ислоҳотлар йўлини қатъий давом эттирамиз (кирил)",[[449,1]],"society"],
  ["Муваффакият сирлари",[[450,1]],"science"],
  ["Бури одам йили",[[451,7]],"world"],
  ["Ибратли эртаклар",[[452,8]],"kids"],
  ["\"Гулаг архипелаги\" 56 жилд",[[453,1]],"world"],
  ["Анор",[[454,5],[755,6]],"uzlit"],
  ["500 харакат уйинлар",[[455,1]],"arts"],
  ["Ги Де Мопасан Туй совгаси",[[456,1]],"world"],
  ["Туркистон: Россия Туркистон, Кукон, Бухоро ваГулжага",[[457,2]],"history"],
  ["Халк бул элим М.Юсуф",[[458,2]],"uzlit"],
  ["8-sinf Ona tili",[[459,9]],"school"],
  ["Никохсиз такилган узук",[[460,1]],"uzlit"],
  ["Турсуной Содикова 1",[[461,2]],"uzlit"],
  ["Cambridge International AS and A Chemistry Workbook",[[462,28]],"cambridge"],
  ["Ўткир Ҳошимов \"Бахор қайтмайди\"",[[463,5]],"uzlit"],
  ["Килич ботир",[[464,1]],"kids"],
  ["Сир очилди",[[465,5]],"uzlit"],
  ["Cambridge Lower Secondary Global Perspectives Stage 7 Learner’s Skills Book",[[466,3]],"cambridge"],
  ["Cambridge International AS & A Level Global Perspectives & Research Digital Teacher’s Resource Access Card",[[467,4]],"cambridge"],
  ["\"Амфибия-одам\"62-жилд(узбек/лотин)",[[468,1]],"world"],
  ["Болалар учун Энисклопедия",[[469,1]],"lang"],
  ["\"Urush va Tinchlik \" 3-4 kitob",[[470,5]],"world"],
  ["Сепсиз киз",[[471,8]],"world"],
  ["Америка фожиаси",[[472,4]],"world"],
  ["Мухаммад Юсуф Алёрим қолур",[[474,1]],"uzlit"],
  ["Уолтер Айзексон: Стив Жобс",[[475,5]],"history"],
  ["Тилга кирган балик",[[476,1],[877,1]],"kids"],
  ["Диёнат О.Ёкубов",[[477,1]],"uzlit"],
  ["STARTING Engilish, 3-синф (К.Инагамова)",[[478,2]],"school"],
  ["Инглиз-узбек-рус расмли лугат 3.Бутаев",[[479,2]],"lang"],
  ["8-sinf Rus tili",[[480,9]],"school"],
  ["Пиноккионинг бошидан кечирганлари",[[481,3]],"kids"],
  ["Рус адабиёти дурдоналари \"Овчининг хотиралари\"12- жилд(узб/лотин).",[[482,3]],"world"],
  ["\"Choliqushi \" P.N.G",[[483,5]],"world"],
  ["Хунарли хор булмасин",[[484,2]],"arts"],
  ["Уч юз олтмиш турт кун (янги натр)",[[485,1]],"uzlit"],
  ["Окшом эртаклари4",[[486,10]],"kids"],
  ["Жирафа нечун хафа",[[487,2]],"kids"],
  ["Бухоро хунармандчилиги дурдоналари",[[488,1]],"arts"],
  ["Толзордан эсган шамол",[[489,6]],"uzlit"],
  ["Юлдузли тунлар",[[490,3],[993,1]],"uzlit"],
  ["Бу ерларда хаёт бошкча",[[491,5]],"world"],
  ["Хазиналар ороли",[[493,2]],"world"],
  ["Шоир севгиси",[[494,8]],"uzlit"],
  ["Янги таҳрирдаги Ўзбекистон Республикасининг Конституциясининг матни А5 форматдаги лотин тилида",[[495,15]],"society"],
  ["9781316637425 Cambridge Checkpoint Mathematics Challenge Workbook 8",[[496,4]],"cambridge"],
  ["7-sinf tasviriy san’at",[[497,6]],"school"],
  ["Мухаммад Юсуф Халима энам аллалари",[[498,5]],"uzlit"],
  ["Марелло",[[499,5]],"world"],
  ["Киёмат",[[500,6]],"world"],
  ["Халоват Т.Малик",[[502,2]],"uzlit"],
  ["Билимли авлод - буюк келажакнинг, тадбиркор хапк - фаровон",[[503,4]],"society"],
  ["Табобат уммонидан томчилар (Шахрбий)",[[504,1]],"science"],
  ["Шаркона тарбия 2",[[505,1],[850,1]],"science"],
  ["9-sinf Chizmachilik",[[506,5]],"school"],
  ["9-sinf Geografiya",[[507,5]],"school"],
  ["О.Генри \"Ишбилармон кишилар\"",[[508,1]],"world"],
  ["Ойнинг олтин уроги (лотин, кайта нашр)",[[509,2]],"kids"],
  ["Тасодифий ихтиролар",[[510,5]],"science"],
  ["Титраётган тог",[[511,5]],"world"],
  ["Мансаб пилла пояси",[[512,1]],"uzlit"],
  ["Эски уйдаги хайкал",[[513,1]],"kids"],
  ["\"Alisherning yoshligi\"Oybek",[[514,5]],"uzlit"],
  ["Зулмат диёрида",[[515,2]],"world"],
  ["Халк огзаки ижоди Равшан",[[516,2]],"uzlit"],
  ["Cambridge Lower Secondary Computing Student’s Book 8 Код ISBN: 9781398369795",[[517,14]],"cambridge"],
  ["9781108744539 Cambridge IGCSE Physics practical Workbook",[[518,8]],"cambridge"],
  ["8-sinf Geografiya",[[519,9]],"school"],
  ["Утган кунлар лотин",[[520,1]],"uzlit"],
  ["Энциклопедия Юнного умника Автомобили",[[521,2]],"lang"],
  ["Турсуной Содикова 6",[[522,2]],"uzlit"],
  ["Абадият конуни",[[523,5]],"world"],
  ["Гурбатда гариб",[[524,5]],"uzlit"],
  ["Cambridge Checkpoint Mathematics Coursebook 9",[[525,28]],"cambridge"],
  ["\"Гилоф бандаси\"25-жилд(узбек/лотин)",[[526,1]],"world"],
  ["Cambridge International AS and A Level Physics,",[[527,28]],"cambridge"],
  ["Cambridge International AS & A Level Global Perspectives & Research Coursebook with Digital Access (2 Years)",[[528,21]],"cambridge"],
  ["Mindset for IELTS CPT",[[529,1]],"cambridge"],
  ["Cambridge International AS and A Chemistry",[[530,28]],"cambridge"],
  ["Чарли ва шоколанд фабрикаси",[[531,5]],"kids"],
  ["Хиёнат кучаси",[[532,2]],"uzlit"],
  ["Темур тузуклари",[[533,10],[673,6]],"history"],
  ["Гугуценинг саргузаштлари",[[534,10]],"kids"],
  ["Самарканд ёхуд зулматда йуколган зиёни излаб... (кирил, янги",[[535,1]],"uzlit"],
  ["Карогимда гуллайди В АТАН (Ахтамкули)",[[536,2]],"world"],
  ["Унта негр боласи",[[537,3]],"world"],
  ["Узбек халк эртаклари Мохир уста",[[538,3]],"kids"],
  ["Энциклопедия Юнного умника Динозавры",[[539,2]],"lang"],
  ["Сунги нидо",[[540,3]],"uzlit"],
  ["Иккинчи сеансга чипта",[[541,5]],"uzlit"],
  ["Менинг номаълум сохиб жамолим",[[542,6]],"uzlit"],
  ["Буюрмаган бойлик",[[543,10]],"uzlit"],
  ["Узбек халк; эртаклари Акл ва бойлик",[[544,3]],"kids"],
  ["Юнон-Рим кураши",[[545,3]],"arts"],
  ["Амур Темур сулоласи П.Равшанов",[[546,1]],"history"],
  ["Гўрўғлининг туғилиши Халқ оғзаки ижоди",[[547,1]],"uzlit"],
  ["Урушнинг аёлдан йирок киёфаси",[[548,2]],"world"],
  ["Суз латофати",[[549,3]],"lang"],
  ["Ок кема",[[550,4],[840,3]],"world"],
  ["Амир Темур Испания элчиси нигохида",[[551,6]],"history"],
  ["Бевафо куп экан",[[552,6]],"uzlit"],
  ["\"Xamsa\" A.Navoiy",[[553,10]],"uzlit"],
  ["Кошинга текизмагин каламни",[[554,4]],"uzlit"],
  ["Бизнинг шахарда угри йук",[[555,7]],"uzlit"],
  ["Мунгли кузлар Х.Тухтабоев",[[556,1]],"uzlit"],
  ["Бобурнома лотин юмшок",[[557,2]],"uzlit"],
  ["Cambridge Checkpiont Lower Secondary Computing 8 Student’s Book Boost eBook 9781398371156",[[558,26]],"cambridge"],
  ["Литературная шкатулка \"Чтение в начальной школе\", №1",[[559,1]],"kids"],
  ["Легенда и мифы народов мира \"Боги Олимпа\"",[[560,1]],"world"],
  ["ХОББИТ, или туда и обратно",[[561,1]],"world"],
  ["Ака -ука грим эртаклари Ялков тукувчи",[[562,1]],"kids"],
  ["Болалар учуй топишмоклар Зарчечак",[[563,2]],"kids"],
  ["Догистон халк эртаклари",[[564,5]],"kids"],
  ["Том тоганинг кулбаси 1-2 китоб",[[565,8]],"world"],
  ["Диалоглар ва матнлар",[[566,1]],"lang"],
  ["Узбек халд эртаклари Иркит Айикча",[[567,1]],"kids"],
  ["Хушкадам",[[568,2]],"uzlit"],
  ["Тиббий кимё, 1-кисм (лотин)",[[570,2]],"school"],
  ["Рухлар исёни",[[571,4]],"uzlit"],
  ["Тошбаканинг уйи",[[572,2]],"kids"],
  ["Ўзбекистон Республикасининг Меҳнат кодекси",[[573,1]],"society"],
  ["Тарбия",[[574,26]],"science"],
  ["Узбек тилининг изохли лугати 5 жилдлик китоби (хар бир туплам 5дона китобдан иборат)",[[575,1]],"lang"],
  ["Географик кашфиётлар энсиқлопедия",[[576,5]],"lang"],
  ["\"Men anglagan hayot\"J.London",[[577,5]],"world"],
  ["Ден Браун:Рақамли қалъа",[[578,5]],"world"],
  ["Такдир уйинлар ёхуд курган кечирганларим",[[580,1]],"history"],
  ["Алкимёгар",[[581,5]],"world"],
  ["Талваса",[[582,2]],"uzlit"],
  ["\"Mindset for IELTS Level 3 Student’s Book with Testbank and Online Modules An Official Cambridge IELTS Course\"",[[583,28]],"cambridge"],
  ["Гарри Поттер ва қақнус ордени",[[584,2]],"world"],
  ["Garri Poter va ajal tuhfasi",[[585,5]],"world"],
  ["Тушлар олами",[[586,4]],"science"],
  ["Олтин кавушча",[[587,5]],"kids"],
  ["Диктант изложения",[[588,4]],"school"],
  ["Мухаммад Юсуф Айтилмаган қўшиқлар",[[589,1]],"uzlit"],
  ["\"Chinor \" A.Muxtor",[[590,5]],"uzlit"],
  ["Севги шундай навбахорки",[[591,5]],"uzlit"],
  ["Балдан сунг",[[592,3]],"world"],
  ["Шифокор табиат асал ва сут",[[593,5]],"science"],
  ["Пахлавой Махмуд Пурёрвалий",[[594,2]],"uzlit"],
  ["Остров сокровищ (переиздание)",[[595,1]],"world"],
  ["Нафосат фалсафаси Эстетика А.Шеров",[[596,2]],"science"],
  ["Кутилмаган вокеа",[[597,1]],"uzlit"],
  ["Улугбек хазинаси",[[598,2]],"uzlit"],
  ["\"Алгимёгар\"",[[599,1]],"world"],
  ["Pure Mathematics 1 for Cambridge International AS & A Level: Print & Online Student Book Pack",[[600,28]],"cambridge"],
  ["\"Qissasi Rabg‘uziy\" Rabg‘uziy",[[601,5]],"uzlit"],
  ["Шерлок Холмс хакидаги хикоялар",[[602,1]],"world"],
  ["8-sinf Biologiya",[[603,9]],"school"],
  ["Pemberton Mathematics for Cambridge IGCSE Teacher Resource Pack: Extended 3rd Edition",[[604,4]],"cambridge"],
  ["Oxford Bookworms Library Stage 2 Bestseller Pack (10)=30",[[605,3]],"english"],
  ["Cambridge Checkpoint Science Workbook 9",[[606,28]],"cambridge"],
  ["Cambridge IGCSE™ Biology Digital Teacher’s Resource Access Card",[[607,2],[1550,2]],"cambridge"],
  ["\"Илтижо\" 54 жилд",[[608,1]],"world"],
  ["Алишер Навоий",[[609,5]],"uzlit"],
  ["Аждодларимиз фожиаси",[[610,5]],"history"],
  ["Аплесин киз",[[611,4]],"kids"],
  ["Узбек халк эртаклари (юмшок)",[[612,7]],"kids"],
  ["Синфдан ташқари ўқиш китоби 3",[[613,1]],"school"],
  ["Усимликлар оламига саёхат",[[614,1]],"science"],
  ["Лобо",[[615,2],[767,1]],"world"],
  ["9781107613331 Cambridge Checkpoint Science Coursebook 7",[[616,24]],"cambridge"],
  ["9781108909150 Cambridge International AS & A Level Global Perspectives & Research Coursebook with Digital Access (2 Years)",[[617,35]],"cambridge"],
  ["Жек Лондон Шимол хикоялари",[[618,1]],"world"],
  ["Осмон кукми зангори",[[620,2]],"uzlit"],
  ["Сув ости маликаси",[[621,1]],"kids"],
  ["Хатар чангалида",[[622,1]],"uzlit"],
  ["Ёш вёртернинг изтироблари",[[623,2],[768,1]],"world"],
  ["Робинзон Крузо",[[624,2]],"world"],
  ["9-sinf Kimyo",[[625,5]],"school"],
  ["Complete Physics for Cambridge – third edition Revision Guide",[[626,1]],"cambridge"],
  ["Анвар Обиджон",[[627,1]],"kids"],
  ["Рус адабиёти дурдоналари \"Русияда ким яхши яшайди?\",8- жилд(узб/лотин).",[[628,2]],"world"],
  ["Maugli",[[629,5]],"kids"],
  ["Узбек болалар адиблари",[[630,20]],"kids"],
  ["Соглом фарзанд оила кувончи",[[631,6]],"science"],
  ["Ажойиб овчи",[[632,5]],"kids"],
  ["Избраное",[[633,6]],"world"],
  ["Сехрли юлдуз",[[634,6]],"kids"],
  ["Асал даволар хазинаси",[[635,1]],"science"],
  ["Халқ бўл элим М.Юсуф",[[636,1]],"uzlit"],
  ["Ирвинг Шоу Ёзги куйлакдаги кизлар",[[637,1]],"world"],
  ["Русские народные сказки 1",[[638,1]],"kids"],
  ["Немис мутафаккирларининг хикматлари (узб/немис)",[[639,1]],"science"],
  ["\"O‘z yurtingdan ayrilma \" Maxtumquli",[[640,5]],"world"],
  ["Уйимни соғиндим",[[641,5]],"uzlit"],
  ["Зулм ва мухаббат",[[642,2]],"uzlit"],
  ["Горио ота",[[643,2]],"world"],
  ["Одатнома 2-китоб",[[644,1]],"science"],
  ["Набор кодексов (Солик кодекси)",[[645,1]],"society"],
  ["Мунгли кўзлар",[[646,2]],"uzlit"],
  ["8-sinf Chizmachilik",[[648,9]],"school"],
  ["Complete Chemistry for Cambridge IGCSE® & O Level Revision Guide",[[649,56]],"cambridge"],
  ["Oxford Bookworms Library Stage 6 Bestseller Pack (8)=24",[[650,3]],"english"],
  ["Essential Chemistry for Cambridge IGCSE by Roger Norris & Lawrie Ryan",[[651,28]],"cambridge"],
  ["Мурожаатнома",[[652,1]],"society"],
  ["Никоб",[[653,6]],"uzlit"],
  ["Сирли гувох",[[654,1]],"world"],
  ["Инглизча-Русча-Узбекча расмли лугат",[[655,4],[925,4]],"lang"],
  ["Cambridge Checkpoint Mathematics Teacher’s Resource 7",[[656,4]],"cambridge"],
  ["\"Одам бўлиш қийин\"",[[657,1]],"uzlit"],
  ["\"Qutadg‘u biligi\"Y.X.Xojib",[[658,5]],"uzlit"],
  ["\"Yer sayyorasi\" G.M.Abakumova",[[659,5]],"science"],
  ["Cambridge International AS and A Level Computer Science Coursebook with Cambridge Elevate Edition (2 Years)",[[660,4]],"cambridge"],
  ["Гарри Поттер ва махфий хона",[[661,2]],"world"],
  ["Шавкат Мирзиёев \"Буюк келажагимизни мард ва олижаноб халқимиз билан қурамиз\"",[[662,3]],"society"],
  ["Марк Менсон:Бепарволикнинг нозик санъати",[[663,5]],"science"],
  ["Навоий Ойбек",[[664,2]],"uzlit"],
  ["Бева",[[665,2]],"uzlit"],
  ["Кора кузлар",[[666,5]],"uzlit"],
  ["Оловли гулдаста",[[667,1]],"uzlit"],
  ["Янги Ўзбекистон тараққиёт стратегияси (лотин)",[[668,1]],"society"],
  ["9-sinf iqtisod",[[669,5]],"school"],
  ["Нурли мангулик (Абдукаххор Иброхимов)",[[670,4]],"uzlit"],
  ["Мушкин кошининг хайъати (Э.Очилов)",[[671,2]],"uzlit"],
  ["Граф Монте Кристо",[[672,4]],"world"],
  ["Ўзбекистон иккинчи жаҳон уруши даврида (лотин)",[[675,2]],"history"],
  ["\"Тинч Дон\" 4 китобли роман,4- китоб",[[676,1]],"world"],
  ["\"Тинч Дон\"(2китобли роман.2-китоб)42-жилд(лотин)",[[677,1]],"world"],
  ["Рус адабиёти дурдоналари \"Диканка кишлоги окшомлари\",6- китоб,(узб/лотин).",[[678,3]],"world"],
  ["Cambridge International AS and A level Biology Coursebook",[[679,28]],"cambridge"],
  ["Асқад Мухтор Чинор",[[680,5]],"uzlit"],
  ["Внекласный чтения",[[681,1]],"kids"],
  ["Хожи Муин",[[682,4]],"uzlit"],
  ["Сафо айвони",[[683,4]],"uzlit"],
  ["Ҳенри Форд: Менинг ҳаётим",[[684,5]],"history"],
  ["Осмон остидаги сир",[[685,2]],"uzlit"],
  ["Алгебра",[[687,10]],"school"],
  ["Надо иметь чуство юмора",[[688,4]],"world"],
  ["Етти мажлис",[[689,5]],"religion"],
  ["Оила",[[690,5],[940,10]],"science"],
  ["Бадминтон",[[691,3]],"arts"],
  ["Бахоуддин Накдшбанд",[[692,2]],"religion"],
  ["Еттинчи курбон",[[693,2]],"uzlit"],
  ["Уткир зехнлилар китоби1",[[694,2]],"science"],
  ["Cambridge Checkpoint Lower Secondary Computing Student’s Book Boost eBook Уровень: 7,8,9 А",[[695,12]],"cambridge"],
  ["Литературная шкатулка \"Чтение в начальной школе\", №3",[[696,1]],"kids"],
  ["Литературная шкатулка \"Чтение в начальной школе\", №2",[[697,1]],"kids"],
  ["Киме олий укув юртларига кирувчи абитуриентлар учун",[[698,2]],"school"],
  ["Гизоли газал",[[700,5]],"uzlit"],
  ["Иблислар",[[701,2]],"world"],
  ["Қобуснома Қайқовус",[[702,1]],"world"],
  ["The Official Cambridge Guide to IELTS Student’s Book",[[703,28]],"cambridge"],
  ["Ҳайвонларнинг ажойиб олами энц",[[704,4]],"science"],
  ["Юлдузлар Айбдор",[[705,5]],"world"],
  ["Афсун",[[706,2]],"uzlit"],
  ["Бир виждон уйгонур",[[707,5]],"uzlit"],
  ["Шайтанат",[[708,10]],"uzlit"],
  ["Дустлар орттириш ва одамларга таъсир утказиш хусусида",[[709,5]],"science"],
  ["Oxford Bookworms Library Stage 1 Bestseller Pack (10)=30",[[710,3]],"english"],
  ["Cambridge Checkpoint Science Teacher’s Resource 7",[[711,4]],"cambridge"],
  ["Ўзбекистон Республикасининг Қизил китоби I",[[712,1]],"science"],
  ["Зулфия \"Бахор келди сени сўроқлаб\"",[[713,1]],"uzlit"],
  ["\"Qiziqarli geografiya\" F.Nazarova",[[714,20]],"science"],
  ["Зарбулмасал",[[715,5]],"uzlit"],
  ["Зураки никох",[[716,1]],"uzlit"],
  ["Соябон",[[717,1]],"uzlit"],
  ["\"Fozil odamlar shahri\" Farobiy",[[718,5]],"science"],
  ["Хаммаси расво",[[719,5]],"uzlit"],
  ["Анна Каренина1-4",[[720,1]],"world"],
  ["Сказки под подушки 3",[[721,2]],"kids"],
  ["Зумрад ва киммат",[[722,2]],"kids"],
  ["Донишманд бобо эртаклари",[[723,10]],"kids"],
  ["Рухият алифбоси",[[724,4]],"uzlit"],
  ["Хамса А.Навоий",[[726,2]],"uzlit"],
  ["Cambridge IGCSE level Computer Science Second Edition coursebook(2years) 9781398318281",[[727,28]],"cambridge"],
  ["Янги таҳрирдаги Ўзбекистон Республикасининг Конституциясининг матни А5 форматдаги кирил тилида",[[728,15]],"society"],
  ["М.Юсуф \"Алёрум қолур\"",[[729,1]],"uzlit"],
  ["\"Mindset for IELTS Level 3 Teacher’s Book with Class Audio",[[730,4]],"cambridge"],
  ["\"So‘z chamani\" Zulfiya",[[731,5]],"uzlit"],
  ["So‘z chamani.A.Oripov",[[732,5]],"uzlit"],
  ["Сунгги илтижо (Юсуф Файзулло)",[[733,2]],"uzlit"],
  ["Funny english",[[734,2]],"lang"],
  ["Набор кодексов (Мехнат кодекси)",[[735,3]],"society"],
  ["Америка фожеаси 1",[[736,2]],"world"],
  ["Қайта туғилган бола",[[737,2]],"uzlit"],
  ["Жахон тарихи кадимги шарк",[[738,2]],"history"],
  ["Complete Physics for Cambridge – third edition Teacher Resource Pack",[[739,1]],"cambridge"],
  ["Ватан согинчи",[[740,5]],"uzlit"],
  ["Жахонгир",[[741,5]],"uzlit"],
  ["Детиктив хикоялар",[[742,5]],"world"],
  ["Она тили савлол жавоблар",[[743,3]],"lang"],
  ["Сукмокдаги сукир саргузаштлари",[[745,8]],"kids"],
  ["Рассказы и басни для детей",[[746,1]],"kids"],
  ["Эртаклар яхшиликка етаклар Бури билан мерган",[[747,1]],"kids"],
  ["8-sinf Jaxon tarixi",[[748,9]],"school"],
  ["Турсуной Содикова 2",[[749,2]],"uzlit"],
  ["Ш.Мирзиёев Нияти улуг халкнинг иши хам улуг хаёти ёруг ва келажаги фаравон булади",[[750,6]],"society"],
  ["Гаройиб скрипка",[[751,4]],"kids"],
  ["Эркин Вохидов Ватан соғинчи",[[752,1]],"uzlit"],
  ["Алишер Навоий асарларида фалаккиёт сирлари",[[753,1]],"uzlit"],
  ["Легенды, мифы, факты Востока (внеклассное чтение по",[[754,1]],"history"],
  ["Баликлар оламига саёхат",[[756,1]],"science"],
  ["Аёллар камок хонасига мактублар",[[757,1]],"uzlit"],
  ["Тенг тенги билан бахтлидир",[[758,2]],"uzlit"],
  ["Иблис салтанати2",[[759,2]],"uzlit"],
  ["\"Ака-ука Карамазовлар\"(узбек/лотин)",[[760,1]],"world"],
  ["\"Санников ери\" 65 жилд",[[761,1]],"world"],
  ["Тоғай Мурод Сайланма",[[762,5]],"uzlit"],
  ["Хазрати Пахловон ота хикоятлари",[[763,15]],"religion"],
  ["Хикматлар ва хикоялар",[[764,6]],"science"],
  ["Болалар учун тез айтишлар Зарчечак",[[765,1]],"kids"],
  ["Кумуш ёгдулар",[[766,1]],"uzlit"],
  ["Жахон тарихи янги давр XV1-XVIII аерлар, 1-кисм (Шухрат Эргашев)",[[769,2]],"history"],
  ["9781108790567 Cambridge Lower Secondary Global Perspectives Stage 9 Learner’s Skills Book",[[770,28]],"cambridge"],
  ["Ўзбекистон Республикасининг Қизил китоби II",[[771,1]],"science"],
  ["Шайтанат 1,2,3",[[772,1]],"uzlit"],
  ["Тохир Малик \"Шайтанат\"1.2.3",[[773,1]],"uzlit"],
  ["Эрнест Миллер Ҳеменгуей Алвидо қурол",[[774,5]],"world"],
  ["Qiziqarli fizika",[[775,5]],"science"],
  ["Халк огзаки ижоди Кунтугмиш",[[776,2]],"uzlit"],
  ["Кумуш лаган савдогари",[[777,5]],"uzlit"],
  ["Номи чикмаган хотин (лотин, кайта нашр)",[[778,2]],"uzlit"],
  ["Қутлуғ қон Ойбек",[[779,1]],"uzlit"],
  ["Яримта нухат",[[780,1],[978,1]],"kids"],
  ["Одам уғрилари",[[781,1]],"world"],
  ["От кишнаган окшом",[[782,2]],"uzlit"],
  ["9781108790512 Cambridge Lower Secondary Global Perspectives Stage 7 Learner’s Skills Book",[[783,25]],"cambridge"],
  ["Бир хумча олтин",[[784,1]],"kids"],
  ["45-майдон",[[785,2]],"uzlit"],
  ["6 тилда расмли мавзули лугат",[[786,1]],"lang"],
  ["Ёзувчининг бахти ва бахтсизлиги",[[787,2]],"uzlit"],
  ["Хукумдорнинг каргиши",[[789,2]],"uzlit"],
  ["Complete Global Perspectives for Cambridge IGCSE® & O Level Teacher Guide",[[790,4]],"cambridge"],
  ["Complete Computer Science for Cambridge IGCSE® & O Level Teacher Guide by Alison Page and David Waters",[[791,4]],"cambridge"],
  ["Хуркитилган туш",[[792,4]],"uzlit"],
  ["Ш.Мирзиёев 1 китоби",[[793,5]],"society"],
  ["Зарубежный писатели",[[794,1]],"world"],
  ["Complete Global Perspectives for Cambridge IGCSE",[[795,56]],"cambridge"],
  ["\"Инсонга олкиш. Орзулар салтанати\" 67-жилд",[[796,1]],"world"],
  ["Garri Poter va hikmatlar toshi",[[797,5]],"world"],
  ["Ярим миллион долларлик килмиш",[[798,1]],"world"],
  ["Узбечка",[[799,2]],"uzlit"],
  ["Узбегим",[[800,2]],"uzlit"],
  ["Энг кадимги хикматлар",[[801,1],[981,6]],"science"],
  ["Хожа Ахрор Валий (3.Исхакова)",[[802,2]],"religion"],
  ["Болалик",[[803,4]],"uzlit"],
  ["Ур тукмок",[[804,5],[848,1]],"kids"],
  ["Cambridge Checkpoint Mathematics Practice book 8",[[805,5]],"cambridge"],
  ["Cambridge Checkpoint Mathematics Practice book 9",[[806,28]],"cambridge"],
  ["\"Олтинчи палата\"26-жилд(лотин)",[[807,1]],"world"],
  ["Рус адабиёти дурдоналари \"Улик Жонлар,5- китоб,(узб/лотин).",[[808,2]],"world"],
  ["Гарри Поттер ва олов қубоки",[[809,2]],"world"],
  ["Boy bola,kambag‘al bola",[[810,5]],"uzlit"],
  ["Жахон мамлакатлари",[[811,1]],"lang"],
  ["Хаёлимда булдинг узун кун Х.Олимжон",[[812,1]],"uzlit"],
  ["Набирамга мактублар",[[813,2]],"science"],
  ["Четдаги одам",[[814,5]],"world"],
  ["10 дан ортиқ қоида",[[815,5]],"science"],
  ["Аскар бола",[[816,4]],"kids"],
  ["C++ Tili Asoslari (Amaliy Qo‘llanma A11+) (А4.5 Yumshoq)-1",[[818,10]],"science"],
  ["МАУГЛИ (лотин)",[[819,2]],"kids"],
  ["Навоий газалиёти талкинлари",[[820,1]],"uzlit"],
  ["Алишер Навоий \"Избранное\" (переиздание)",[[821,2]],"uzlit"],
  ["Богбоннинг пушаймони",[[822,2]],"kids"],
  ["Чойнома",[[823,5]],"arts"],
  ["Бу жуда қизиқ",[[824,10]],"science"],
  ["Ал Мухтасимга якинлашув",[[825,5]],"world"],
  ["Ахлокнинг асосий меъёрлари",[[826,5]],"science"],
  ["Ширин ковунлар мамлакати",[[827,5]],"kids"],
  ["Сунги ук",[[828,5]],"uzlit"],
  ["Алиса мужизалар мамлакатида",[[829,3]],"kids"],
  ["Жониворлар саргузаштлари Узб халк эртаклари",[[831,2]],"kids"],
  ["Агата Кристи \"Ўнта негир боласи\"",[[832,1]],"world"],
  ["Машхур кишилар хаётидан Д.Карнеги",[[833,1]],"history"],
  ["Темур тузуклари узбекистон",[[834,2]],"history"],
  ["Янги таҳрирдаги Ўзбекистон Республикасининг Конституциясининг матни А4 форматдаги рус тилида",[[835,4]],"society"],
  ["9781398369795-Cambridge Lower Secondary Computing 8 Student’s Book",[[836,12]],"cambridge"],
  ["Муаллак минора",[[837,2],[875,1]],"uzlit"],
  ["Такдирдан кочиб булмас",[[838,2]],"uzlit"],
  ["Гур кизи А.коржонов",[[839,1]],"uzlit"],
  ["Золота эмира",[[841,4]],"history"],
  ["Урта аср Тарихий шахслари",[[842,3]],"history"],
  ["Oxford Bookworms Library Stage 5 Bestseller Pack (8)=24",[[843,3]],"english"],
  ["Cambridge International AS and A level Biology practical Workbook",[[844,28]],"cambridge"],
  ["Подводньй мир",[[845,5]],"science"],
  ["Муттивой",[[846,10]],"uzlit"],
  ["Борлик ва йуклик 1- 2 китоблар",[[847,12]],"science"],
  ["Абдулхамид Чулпон Қор кўйнидаги лола",[[849,1]],"uzlit"],
  ["Менинг юлдузларим Э.Вохидов",[[851,2]],"uzlit"],
  ["Кухна дунё Одил Ёкубов",[[852,1]],"uzlit"],
  ["Cambridge Checkpiont Lower Secondary Computing 7 Student’s Book Boost eBook 9781398371149",[[853,26]],"cambridge"],
  ["Узбекистоннинг ёввоийи манзарали усимликлари",[[854,2]],"science"],
  ["Хаёл макбараси",[[855,4]],"uzlit"],
  ["Севги сози",[[856,5]],"uzlit"],
  ["Сохибкирон абадияти 1-2 китоб",[[857,4]],"history"],
  ["Лев Толстой Энг сара асарлари",[[858,5]],"world"],
  ["Лутфулло Жўраев Инглизча-ўзбекча-русча Ўқув луғати",[[859,5]],"lang"],
  ["Оскар Уайлд:Дориан Грейнинг портрети",[[860,5]],"world"],
  ["Весёлке цифры",[[861,8]],"kids"],
  ["Махтумкулинома (О.Ягмур)",[[862,2]],"world"],
  ["Хрестоматия литературных произведения 3",[[863,3]],"school"],
  ["Ёлгон умидлар дашти Т.Малик",[[864,1]],"uzlit"],
  ["Тушда кечган умирлар",[[865,2]],"uzlit"],
  ["Cambridge Checkpoint Science Workbook 7",[[866,28]],"cambridge"],
  ["Супер физика",[[867,5]],"science"],
  ["Узбек халк; эртаклари Сунбил билан Гулшан",[[868,1]],"kids"],
  ["Олтин калит буратино",[[869,3]],"kids"],
  ["Ўзбекистон Иккинчи жаҳон уруши даврида туркумидаги китоб-албом (лотин)",[[870,2]],"history"],
  ["9781398369320-Cambridge Lower Secondary Computing 7 Student’s Book",[[871,12]],"cambridge"],
  ["Complete Computer Science for Cambridge IGCSE® & O Level by Alison Page and David Waters",[[872,56]],"cambridge"],
  ["Cambridge Checkpoint Science Coursebook 8",[[873,28]],"cambridge"],
  ["Янги Ўзбекистон демократик ўзгаришлар, кенг имкониятлар ва амалий ишлар мамлакатига айланмоқда",[[874,8]],"society"],
  ["Тулкивойнинг саргузаштлари",[[876,1]],"kids"],
  ["Буюрмаган бойлик жахон адабиёти",[[878,1]],"world"],
  ["Русские народные сказки 2",[[879,1]],"kids"],
  ["Топталган гулбадан",[[880,3]],"uzlit"],
  ["Cambrige IGCSE level Computer Science Second Edition teacher’s book(2years) 9781398318502",[[881,2]],"cambridge"],
  ["Шайх Нажмиддин Кубро (3.Исхакова)",[[882,2]],"religion"],
  ["Узбекистон Республикасининг Конституцияси (узбек/кирил)",[[883,2]],"society"],
  ["Кор маликаси",[[884,6]],"kids"],
  ["Набор кодексов (Маъмурий жавобгарлик тўғрисидаги кодекс)",[[885,1]],"society"],
  ["9781108790574 Cambridge Lower Secondary Global Perspectives Stage 9 Teacher’s Book",[[886,4]],"cambridge"],
  ["Шайтонваччанинг найранглари 4",[[887,2]],"kids"],
  ["Ойбек Навоий",[[888,1]],"uzlit"],
  ["Узбекистан в годы второй мировой войны",[[890,1]],"history"],
  ["Вольная борьба",[[891,3]],"arts"],
  ["\"Ок тун\"47-жилд(шеълар ва достанлар",[[892,1]],"world"],
  ["\"Хилват ҳиёбонлар\"(лотин) 60-жилд",[[893,1]],"world"],
  ["\"Qobusnoma\"Kaykovus",[[894,5]],"world"],
  ["Элиф Шафақ:Ишққа оид 40 қоида",[[895,5]],"world"],
  ["Шахзода ва гадо",[[896,5]],"world"],
  ["Анна Каренина5-8",[[897,1]],"world"],
  ["Нозикой ва Маймоқ",[[898,20]],"kids"],
  ["Анушшох",[[899,4]],"uzlit"],
  ["Бобурнома",[[900,5]],"uzlit"],
  ["Болалар учун хикоялар",[[901,8]],"kids"],
  ["Жосуслар уйини",[[902,5]],"world"],
  ["Катта умидлар 1-2 китоблар",[[903,12]],"world"],
  ["Болалар учун маколлар Зарчечак",[[904,1]],"kids"],
  ["Сказка для детей Летучий корабль",[[905,1]],"kids"],
  ["Cambridge International AS and A Chemistry practical",[[907,28]],"cambridge"],
  ["Диққат:Чалғитувчи дунёда муваффақият сирлари",[[908,4]],"science"],
  ["Узбекистон Республикасининг Конституцияси (узбек/лотин)",[[909,2]],"society"],
  ["Сулаймон Бокиргоний (Хаким ота) (У.Ембергенов)",[[910,1]],"religion"],
  ["Домино",[[911,2]],"uzlit"],
  ["Иблис салтанатиЗ",[[913,2]],"uzlit"],
  ["8-sinf Adabiyot",[[914,9]],"school"],
  ["Болалар учуй тез айтишлар Зарчечак",[[915,2]],"kids"],
  ["Женни Герхард",[[916,2]],"world"],
  ["Дунё Сиёсат Жамият",[[917,2]],"society"],
  ["9-sinf Biologiya",[[918,5]],"school"],
  ["Cambridge Checkpoint Mathematics Teacher’s Resource 9",[[919,4]],"cambridge"],
  ["Супер математика",[[920,9]],"science"],
  ["Всё красное",[[921,4]],"world"],
  ["Жим Рон",[[922,1]],"science"],
  ["Мета хикоялар оралаб",[[923,4]],"uzlit"],
  ["Шохчарбог тонги",[[924,5]],"uzlit"],
  ["Болалар учун топишмоклар шерлар За",[[926,1]],"kids"],
  ["Халоват Тохир Малик",[[927,1]],"uzlit"],
  ["Лев Толстой Балдан сунг",[[928,1]],"world"],
  ["Оскард Уайлд",[[929,5]],"world"],
  ["Жорж Оруэлл: Молхона",[[930,5]],"world"],
  ["\"Лочин хакила кушик\"",[[931,1]],"world"],
  ["Cambridge International AS and A level Biology Workbook",[[932,28]],"cambridge"],
  ["Аламазон ва унинг пиёдалари",[[933,2]],"kids"],
  ["Машраб (тарих ва шахе), Замира Исхокова",[[934,2]],"history"],
  ["Термизийларнинг илмий тафаккури",[[935,2]],"religion"],
  ["Жасур киз",[[936,2]],"kids"],
  ["Ок тепалик уғри",[[937,1]],"uzlit"],
  ["Тузоқ",[[939,5]],"uzlit"],
  ["Амир Темур салтанати",[[941,3]],"history"],
  ["Яхшидан буюклик сари",[[943,1]],"science"],
  ["The Official Cambridge Guide to IELTS Student’s Book with Answers with DVD-ROM",[[944,28]],"cambridge"],
  ["Паралимпия харакати",[[945,3]],"arts"],
  ["Стивен Р.Кови: Муваффақиятли инсонларнинг 7 кўникмаси",[[946,5]],"science"],
  ["Алкимёгар лотин",[[947,2]],"world"],
  ["Хаёт ва момот",[[948,4]],"uzlit"],
  ["Чоликуши",[[949,3]],"world"],
  ["Алпомиш Халқ оғзаки ижоди",[[950,1]],"uzlit"],
  ["Шум бола",[[951,3]],"uzlit"],
  ["Канфуций",[[952,5]],"science"],
  ["Аросатдаги одамлар",[[953,8]],"uzlit"],
  ["\"Хорланганлар ва хақоратланганлар\"(узбек/лотин)",[[954,1]],"world"],
  ["Эртаклар яхшиликка етаклар Канизак билан подшох",[[955,1]],"kids"],
  ["Уткир зехнлилар китобиЗ",[[956,2]],"science"],
  ["Бу азиз дунё",[[957,3]],"uzlit"],
  ["М.Булгаков “Избранное \"Собачье сердце\" (переиздание)",[[958,2]],"world"],
  ["9781398369825-Cambridge Lower Secondary Computing 9 Student’s Book",[[959,12]],"cambridge"],
  ["Тафаккур кемаси",[[960,5]],"uzlit"],
  ["Адашганлар",[[961,2]],"uzlit"],
  ["Cambridge AS and A level Physics revision guide",[[962,28]],"cambridge"],
  ["Чингиз Айтматов Жамила",[[963,5]],"world"],
  ["Tarbiya kitobi",[[964,5]],"science"],
  ["\"Ufq\" S.Ahmad",[[965,5]],"uzlit"],
  ["Кушлар дунёсига саёхат",[[966,1]],"science"],
  ["Рамзлар силсиласи (лотин, кайта нашр)",[[967,1]],"world"],
  ["Кичик дурдоналар",[[968,4]],"kids"],
  ["Внеклассное чтение 4",[[969,5]],"kids"],
  ["8-sinf O‘zbekiston davlati va huquq asoslari",[[970,9]],"school"],
  ["\"Доктор Живаго\" 55-жилд",[[971,1]],"world"],
  ["Баскетбол",[[972,3]],"arts"],
  ["\"Икки капитан\"63-жилд(узбек/лотин)",[[973,1]],"world"],
  ["Саробга алданганлар кисмати",[[974,6]],"society"],
  ["Ишбилармон кишилар",[[975,4]],"science"],
  ["Тукилаётган япроклар",[[976,4]],"uzlit"],
  ["Бу дунёда улиб булмайди",[[977,4]],"uzlit"],
  ["Болалигим кайтмас бахорим",[[979,6]],"uzlit"],
  ["Спитамен",[[980,3]],"uzlit"],
  ["Ортда колган йул",[[982,1]],"uzlit"],
  ["Янги таҳрирдаги Ўзбекистон Республикасининг Конституциясининг матни А5 форматдаги рус тилида",[[983,13]],"society"],
  ["Волейбол мусобака ўтказиш тартиби ва қоидалари",[[984,3]],"arts"],
  ["Гарри Поттер ва Азқабан махбуси",[[985,2]],"world"],
  ["Юмшоқой исмли типратиканча",[[986,10]],"kids"],
  ["Афгон киз",[[987,1]],"uzlit"],
  ["Аёлга касида Сайланма (кайта нашр)",[[988,2]],"uzlit"],
  ["Улисс саргузаштлари",[[989,1]],"world"],
  ["Нияти улуг халкнинг - иши хам улуг, хаёти ёруг ва келажаги",[[990,3]],"society"],
  ["Ака -ука грим эртаклари Уч ип йигирувчи",[[991,1]],"kids"],
  ["Америка фожеаси 2",[[992,2]],"world"],
  ["Стол теннис ўйинига дастлабки ўргатиш усуллари",[[994,3]],"arts"],
  ["Сичкончанинг саргузаштлари",[[995,5]],"kids"],
  ["Тугри суз Ахмад",[[996,4]],"uzlit"],
  ["English-Russian-Uzbek dictionary",[[997,4]],"lang"],
  ["Бола одоби билан азиз",[[998,1]],"science"],
  ["9781108797795 Cambridge International AS & A Level Biology Digital Teacher’s Resource Access Card",[[999,2]],"cambridge"],
  ["Бобур йулбарс",[[1000,2]],"uzlit"],
  ["Хрестоматия литературных произведения 2",[[1001,3]],"school"],
  ["Cambridge IGCSE® Physics Workbook",[[1002,28]],"cambridge"],
  ["Узбегим Эркин Вохидов",[[1003,1]],"uzlit"],
  ["8-sinf O‘zbekiston tarixi",[[1005,9]],"school"],
  ["Шайтонваччанинг найранглари 3",[[1006,2]],"kids"],
  ["Cambridge Lower Secondary Global Perspectives Stage 8 Learner’s Skills Book",[[1007,28]],"cambridge"],
  ["Рус адабиёти дурдоналари \"Думбул бойвачча\"17- жилд(узб/лотин).",[[1008,2]],"world"],
  ["Cambridge International AS and A Level Physics, Coursebook",[[1009,28]],"cambridge"],
  ["\"If qal’asining mahbusi\" Graf Monte Kristo",[[1010,10]],"world"],
  ["Гаройиб такдирлар",[[1011,2]],"uzlit"],
  ["Инглиз тили \"STARTING Engilish\", 2-синф (машк дафтари)",[[1012,4]],"school"],
  ["Тагоб қишлоқ эртаклари",[[1013,5]],"kids"],
  ["Киз болага тош отманг",[[1014,4]],"uzlit"],
  ["Пагани скрипкаси",[[1015,7]],"world"],
  ["Хумоюн ва Акбар П.Крдиров",[[1016,1]],"uzlit"],
  ["Навоий лирикаси (Абдукодир Хайитметов)",[[1017,1]],"uzlit"],
  ["Анъанавий ғижжак дарслиги QR-код",[[1018,13]],"arts"],
  ["Imom Termiziy брошюра",[[1019,5]],"religion"],
  ["Ўзбек тили меъёрлари (пунктуация) китоби",[[1020,2]],"lang"],
  ["Рус адабиёти дурдоналари \"Чингизхон ва Ботухон\", 94-жилд (лотин)",[[1021,1]],"world"],
  ["Узбекистон тарихи 7 синф №1473624 14.07.2023г",[[1022,27]],"school"],
  ["Жадидлар тўплами",[[1023,1]],"history"],
  ["Имом Мотирудий хаёти ва илмий меросига бағишланган плакат",[[1024,4]],"religion"],
  ["Абу Райхон Беруний хаёти ва илмий меросига бағишланган плакат",[[1025,4]],"history"],
  ["Узбек тарих (Дарслик 7- синф)",[[1026,25]],"school"],
  ["Максудам Омон Матжон",[[1027,5]],"uzlit"],
  ["Афандининг афандилари(Муҳаббатнинг вазни) А.Обрўев",[[1028,5]],"uzlit"],
  ["Табий фан 6 синф",[[1029,26]],"school"],
  ["Абдулла Аъзам Аброрлар хайрати (лотин)",[[1030,5]],"uzlit"],
  ["Анъанавий рубоб дарслиги QR-код",[[1031,13]],"arts"],
  ["Х,амид Гулом сайланма",[[1032,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Паганин қисмати\", 99-жилд (лотин)",[[1033,1]],"world"],
  ["Рус адабиёти дурдоналари \"Боғбон\", 83-жилд (лотин)",[[1034,1]],"world"],
  ["\"Манавият.Асосий тушунчалар лугати\"",[[1035,1]],"lang"],
  ["Руский язик 9 синф",[[1036,26]],"school"],
  ["Ватан учун яшайлик",[[1037,5]],"society"],
  ["Сузмунчок С. САЙЙИД (лотин)",[[1038,5]],"uzlit"],
  ["Mirzo Ulug‘bek брошюра",[[1039,5]],"history"],
  ["Бобомнинг боглари Зикрилло Неъмат",[[1040,2]],"uzlit"],
  ["Бир жуфт суз Р Мусурмонов",[[1041,5]],"uzlit"],
  ["Yuridik terminlarning ruscha-o‘zbekcha lug‘ati",[[1042,1]],"lang"],
  ["Йулдаман, нурли йулда Б Мажид (лотин)",[[1043,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Қирғоқ\", 32-жилд (лотин)",[[1044,1]],"world"],
  ["Давлат тилида иш юритиш (лотин)",[[1045,5]],"lang"],
  ["Сўз чамани ичра наво кўргузиб А.Алимбеков",[[1046,5]],"uzlit"],
  ["Куз сонатаси Мухиддин Омон",[[1047,5]],"uzlit"],
  ["Абдукаххор Ибрагимов замондошлар хотирасида",[[1048,2]],"history"],
  ["Рус адабиёти дурдоналари \"Тунги қуёш\", 84-жилд (лотин)",[[1049,1]],"world"],
  ["Руский язик 7 синф",[[1050,19]],"school"],
  ["Газал гизоли Шоира Шаме",[[1051,5]],"uzlit"],
  ["(Капалак кушиги)Шом товуши Шухрат Ориф",[[1052,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Уч бақалоқ\", 98-жилд (лотин)",[[1053,1]],"world"],
  ["Садриддин Салим Бухорий сайланма",[[1054,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Қафасдаги қуш\", 100-жилд (лотин)",[[1055,1]],"world"],
  ["\"Кутубхонада иш юритиш\" амалий кулланма",[[1056,1]],"other"],
  ["Аксинча Носиржон Жураев",[[1057,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Оқ камалак\", 75-жилд (лотин)",[[1058,1]],"world"],
  ["Рус адабиёти дурдоналари \"Мценск уездидан чиққан Макбет хоним\", 72-жилд (лотин)",[[1059,1]],"world"],
  ["Ijtimoiy-siyosiy terminlarning qisqacha lug‘ati",[[1060,1]],"lang"],
  ["Адабиёт 6 синф",[[1061,26]],"school"],
  ["Узбекистон Кахрамонлари (Китоб-альбом)",[[1062,1]],"history"],
  ["Диёрим Журабек Жахон",[[1063,5]],"uzlit"],
  ["Окибат Рауф Субхон",[[1064,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Кечмиш ва ўйлар\", 29-жилд (лотин)",[[1065,1]],"world"],
  ["Рус адабиёти дурдоналари \"Рус ўрмони\", 71-жилд (лотин)",[[1066,1]],"world"],
  ["Жахон-тарихи 10 синф",[[1067,26]],"school"],
  ["Абдусаид Кучимов Наср 2",[[1068,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Кўрфаз ёғдуси\", 85-жилд (лотин)",[[1069,1]],"world"],
  ["Жахон тарихи 7 синф",[[1070,26]],"school"],
  ["Эътироф Абдулла Орипов",[[1071,5]],"uzlit"],
  ["Согинч шивирлари 3. Хужаниёзова",[[1072,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Тунги бинафша\", 38-жилд (лотин)",[[1073,1]],"world"],
  ["Анъанавий най дарслиги QR-код",[[1074,13]],"arts"],
  ["Адиблар хиёбони албом",[[1075,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Денгиз эгизим менинг\", 78-жилд (лотин)",[[1076,1]],"world"],
  ["Руский язик 10 синф",[[1077,26]],"school"],
  ["Рус адабиёти дурдоналари \"Мухтор вазирнинг улими\", 90-жилд (лотин)",[[1078,1]],"world"],
  ["География (Дарслик 7- синф)",[[1079,26]],"school"],
  ["Рус адабиёти дурдоналари \"Ухлар эди олтин булутча\", 87-жилд (лотин)",[[1080,1]],"world"],
  ["Перекасающиеся параллели Н Илин",[[1081,5]],"world"],
  ["Рус адабиёти дурдоналари \"Булбул чамани\", 61-жилд (лотин)",[[1082,1]],"world"],
  ["Рус адабиёти дурдоналари \"Фома Гордеев\", 35-жилд (лотин)",[[1083,1]],"world"],
  ["Чингиз Айтматов сайланма",[[1084,2]],"world"],
  ["Олов сузлар инглизча",[[1085,5]],"lang"],
  ["Шалола туплам",[[1086,5]],"uzlit"],
  ["Турналар охи (Армон) Т Тиллаев",[[1087,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Волоколамск йўлида\", 69-жилд (лотин)",[[1088,1]],"world"],
  ["Рус адабиёти дурдоналари \"Москва афсонаси\", 82-жилд (лотин)",[[1089,1]],"world"],
  ["Рус адабиёти дурдоналари \"Телба\", 21-жилд (лотин)",[[1090,1]],"world"],
  ["Imom Moturudiy брошюра",[[1091,5]],"religion"],
  ["Руский язик 5 синф",[[1092,12]],"school"],
  ["Harbiy atamalarning izohli lug‘ati kitobi",[[1093,1]],"lang"],
  ["Рус адабиёти дурдоналари \"Тиниқ кўллар\", 88-жилд (лотин)",[[1094,1]],"world"],
  ["Рус адабиёти дурдоналари \"Соҳилдаги уй\", 77-жилд (лотин)",[[1095,1]],"world"],
  ["Рус адабиёти дурдоналари \"Оқ ва қора\", 37-жилд (узбек/лотин)",[[1096,1]],"world"],
  ["Матёкуб Кушжонов сайланма",[[1097,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Нима қилмоқ керак?\", 27-жилд (лотин)",[[1098,1]],"world"],
  ["Рус адабиёти дурдоналари \"Саркаш дарё\", 92-жилд (лотин)",[[1099,1]],"world"],
  ["Инглиз-тили 6 синф",[[1100,26]],"school"],
  ["Тасвирий санъат 6 синф",[[1101,26]],"school"],
  ["Яхшидир аччиц хакикат Г. Умарова",[[1102,2]],"uzlit"],
  ["Bank moliya terminlari",[[1103,1]],"lang"],
  ["Рус адабиёти дурдоналари \"Дерсу узала\", \"Менинг аксим йўқ сурат\", 68-жилд (лотин)",[[1104,1]],"world"],
  ["Абу Али Ибн Сино хаёти ва илмий меросига бағишланган плакат",[[1105,4]],"history"],
  ["Мухаббатга кум дилни Фарогат Худойкулова",[[1106,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Севги садоси\", 40-жилд (лотин)",[[1107,1]],"world"],
  ["Рус адабиёти дурдоналари \"Баҳорнинг ўн етти лаҳзаси\", \"Арбат болалари\", 49-жилд (лотин)",[[1108,1]],"world"],
  ["Анъанавий дутор дарслиги QR-код",[[1109,13]],"arts"],
  ["Рус тили (Дарслик 8- синф)",[[1110,26]],"school"],
  ["Рус адабиёти дурдоналари \"Улуғ Пётр\", 41-жилд (лотин)",[[1111,1]],"world"],
  ["Ўзбекистон жой номлари",[[1112,1]],"lang"],
  ["\"Ўзбекистон Иккинчи жаҳон уруши даврида\" китоб лотин алифбосида",[[1113,2]],"history"],
  ["Рус тили (Дарслик 7- синф)",[[1114,7]],"school"],
  ["Уткир Хошимов сайланма",[[1115,2]],"uzlit"],
  ["Она тилим -мангу маконим",[[1116,1]],"lang"],
  ["Имом Бухорий хаёти ва илмий меросига бағишланган плакат",[[1117,4]],"religion"],
  ["Алп Жамол сайланма",[[1118,2]],"uzlit"],
  ["Alisher Navoiy брошюра",[[1119,5]],"history"],
  ["Мангу кушик Мирпулат Мирзо",[[1120,5]],"uzlit"],
  ["Одамлардан тинглаб хикоя X. Султонов (лотин)",[[1121,5]],"uzlit"],
  ["Ahmad Farg‘oniy брошюра",[[1122,5]],"history"],
  ["Уйгон, миллат Абдулла Авлоний",[[1123,5]],"uzlit"],
  ["Мухаббат нишони Бобур",[[1124,5]],"uzlit"],
  ["Шамол йули Жумагул Сувонова",[[1125,5]],"uzlit"],
  ["Ёнарди кунглим Шукур Курбон",[[1126,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"12 стул\", \"Олтин бузоқ\", 48-жилд (лотин)",[[1127,1]],"world"],
  ["Рус адабиёти дурдоналари \"Ҳаёт ва қисмат\" 95-жилд (лотин)",[[1128,1]],"world"],
  ["Мирзо Улуғбек хаёти ва илмий меросига бағишланган плакат",[[1129,4]],"history"],
  ["Тасвирий санъат 7 синф",[[1130,26]],"school"],
  ["Эркин Аъзам танланган асарлар 4 том",[[1131,2]],"uzlit"],
  ["O‘zbek tili meyorlari (punktuatsiya) kitobi",[[1132,1]],"lang"],
  ["Abu Ali Ibn Sino брошюра",[[1133,5]],"history"],
  ["Руский язик 11 синф",[[1134,26]],"school"],
  ["\"Юрт гамхури керак менга\" Бердах",[[1135,5]],"uzlit"],
  ["Рус адабиёти дурдоналари Ит юрак\", 52-жилд (лотин)",[[1136,1]],"world"],
  ["Bahovuddin Naqshband брошюра",[[1137,5]],"religion"],
  ["Рус адабиёти дурдоналари \"Оқ бим қорақулоқ\", 89-жилд (лотин)",[[1138,1]],"world"],
  ["\"Ижод боғидан гулдаста\" шеърлар тўплами",[[1139,2]],"uzlit"],
  ["Она-тили 6 синф",[[1140,26]],"school"],
  ["Баховуддин Нақшбанд хаёти ва илмий меросига бағишланган плакат",[[1141,4]],"religion"],
  ["Jadidlar(har to‘plamda 8 dona)",[[1142,5]],"history"],
  ["Ветер моего края Николай Илин цаттик",[[1143,5]],"world"],
  ["Куксимдаги нур Г. Матёкубова",[[1144,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Уста ва Маргарита\", 51-жилд (узбек/лотин)",[[1145,1]],"world"],
  ["Келажакка бошлайди ишонч",[[1146,5]],"society"],
  ["Омонат ва матонат Кулман Очил",[[1147,5]],"uzlit"],
  ["Имом Термизий хаёти ва илмий меросига бағишланган плакат",[[1148,4]],"religion"],
  ["Рус тили (Дарслик 5- синф)",[[1149,14]],"school"],
  ["Бобосуз изидан Э. Шукуров",[[1150,5]],"uzlit"],
  ["Ахмад Фарғоний хаёти ва илмий меросига бағишланган плакат",[[1151,4]],"history"],
  ["Марокли фасллар, эъзозли мусоҳиблар.Хамидулла Акбаров",[[1152,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Лев Толстой\", 93-жилд (лотин)",[[1153,1]],"world"],
  ["Она тили 7 синф",[[1154,26]],"school"],
  ["Юраётган йуллар Турсун Али",[[1155,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Москва ва москваликлар\", 11-жилд (лотин)",[[1156,1]],"world"],
  ["Руский язик 6 синф",[[1157,26]],"school"],
  ["Олим Отахон сайланма",[[1158,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Привалов миллионлари\", 64-жилд (лотин)",[[1159,1]],"world"],
  ["Саъдулла Хаким танланган асарлар",[[1160,2]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Қотил маросимига марҳамат\", 73-жилд (лотин)",[[1161,1]],"world"],
  ["Рус адабиёти дурдоналари \"Иван Денисовичнинг бир куни\", 57-жилд (лотин)",[[1162,1]],"world"],
  ["Рус адабиёти дурдоналари \"Сенинг исминг\", 74-жилд (лотин)",[[1163,1]],"world"],
  ["\"2017-2021 йиллар учун Ўзбекистон Республикаси Илф-фан ва инновациялар бўйича миллий маъруза китоби\"",[[1164,1]],"society"],
  ["Девон Тухтамиш Тухтаев",[[1165,5]],"uzlit"],
  ["Узбекистоним Абдулла Орипов",[[1166,2]],"uzlit"],
  ["Тебя люблю я, жизнь Алишер Навоий",[[1167,5]],"uzlit"],
  ["Рус адабиёти дурдоналари \"Бу менинг қўшиғим, сиз куйлаётган...\", \"Асов отлар\" 79-жилд (лотин)",[[1168,1]],"world"],
  ["Abu Rayhon Beruniy брошюра",[[1169,5]],"history"],
  ["Янги Ўзбекистон меъмори",[[1170,2]],"society"],
  ["Тонг тушлари Фахриддин Хайит",[[1171,5]],"uzlit"],
  ["Озод Шарофуддинов сайланма",[[1172,2]],"uzlit"],
  ["Шароф Бошбеков танланган асарлар",[[1173,2]],"uzlit"],
  ["Анъанавий танбур QR-код",[[1174,13]],"arts"],
  ["Imom Buxoriy брошюра",[[1175,5]],"religion"],
  ["\"Анъанавий дойра дарслиги QR-код \"",[[1176,13]],"arts"],
  ["Рус адабиёти дурдоналари \"Шарафли умр\", 81-жилд (лотин)",[[1177,1]],"world"],
  ["Ижтимоий-сиёсий терминлар қисқача изоҳли луғати",[[1178,2]],"lang"],
  ["Муҳаммад Хоразмий хаёти ва илмий меросига бағишланган плакат",[[1179,4]],"history"],
  ["Мулку миллатга эмин улга агар огохлар",[[1180,5]],"society"],
  ["Рус адабиёти дурдоналари \"Жиноят ва жазо\", 20-жилд (лотин)",[[1181,1]],"world"],
  ["Рус адабиёти дурдоналари \"Омон бўлсанг унутма\" 97-жилд (лотин)",[[1182,1]],"world"],
  ["Рус адабиёти дурдоналари \"Ўрмонлар орасида\", 76-жилд (лотин)",[[1183,1]],"world"],
  ["Рус адабиёти дурдоналари \"Пряслинлар\" 80-жилд (лотин)",[[1184,1]],"world"],
  ["Янги Ўзбекистон (лотин)",[[1185,2]],"society"],
  ["Абдулла Шер сайланма",[[1186,2]],"uzlit"],
  ["So‘z hiyoboni kitobi",[[1187,1]],"lang"],
  ["Milliy o‘zlik va mustaqil davlatchilik timsoli",[[1188,1]],"society"],
  ["Рус адабиёти дурдоналари \"Хаёл чечаклари\", 96-жилд (узбек/лотин)",[[1189,1]],"world"],
  ["Рус адабиёти дурдоналари \"Петербургдан Москвага саёҳат\", 30-жилд (лотин)",[[1190,1]],"world"],
  ["Muhammad Xorazmiy брошюра",[[1191,5]],"history"],
  ["Рус адабиёти дурдоналари \"Кўришмаймиз энди сен билан\", 66-жилд (лотин)",[[1192,1]],"world"],
  ["Элдошларим, Дилдошларим С. Саййид",[[1193,2]],"uzlit"],
  ["Эркин Аъзам танланган асарлар 3 том",[[1194,2]],"uzlit"],
  ["Куртакда дарахтни курмок Вафо Файзулла",[[1195,5]],"uzlit"],
  ["Алишер Навоий хаёти ва илмий меросига бағишланган плакат",[[1196,4]],"history"],
  ["Солнома \"Ўзбекистон Республикаси Президенти Ш.М.Мирзиёев фаолияти хроникаси\" ўзбек лотин",[[1197,1]],"society"],
  ["Рус адабиёти дурдоналари \"Иблислар\", 23-жилд (лотин)",[[1198,1]],"world"],
  ["Узим хар жойдаман, кунглим сандадур",[[1199,5]],"uzlit"],
  ["Халима Худойбердиева сайланма",[[1200,2]],"uzlit"],
  ["Умр дафтари Гофур Гулом",[[1201,5]],"uzlit"],
  ["Turkman mumtoz she’riyati antologiyasi",[[1202,1]],"world"],
  ["Ijod bog‘idan guldasta 6-son",[[1203,2]],"uzlit"],
  ["Ijod bog‘idan guldasta",[[1204,2]],"uzlit"],
  ["Xoja Ahmad Yassaviy, Sulaymon Boqirg‘oniy",[[1205,1]],"uzlit"],
  ["Ogahiy",[[1206,1]],"uzlit"],
  ["Xolida Adib Adivar, Said Foyiq Abasiyoniq",[[1207,1]],"world"],
  ["Turk zamonaviy she’riyati antologiyasi",[[1208,1]],"world"],
  ["Mar Boyjiyev, Murza G‘aparov",[[1209,1]],"world"],
  ["Anvar Olimjonov",[[1210,1]],"uzlit"],
  ["Halima Xudoyberdiyeva",[[1211,1]],"uzlit"],
  ["Qirg‘iz zamonaviy nasri antologiyasi",[[1212,1]],"world"],
  ["Hamid Olimjon Zulfiya",[[1213,1]],"uzlit"],
  ["Qoraqalpoq zamonaviy nasri antologiyasi",[[1214,1]],"uzlit"],
  ["Oybek",[[1215,1]],"uzlit"],
  ["Qozoq zamonaviy she’riyati antologiyasi",[[1216,1]],"world"],
  ["Husayn Jovid",[[1217,1]],"world"],
  ["Mashrab, So‘fi Olloyor",[[1218,1]],"uzlit"],
  ["Mahmud Koshg‘ariy",[[1219,1],[1269,1]],"uzlit"],
  ["Anar",[[1220,1]],"world"],
  ["Abay, Jambul",[[1221,1]],"world"],
  ["G‘ofur G‘ulom",[[1222,1]],"uzlit"],
  ["Sarchashma",[[1223,1]],"uzlit"],
  ["Yavuz Bahodiro‘g‘li",[[1224,1]],"world"],
  ["Kunxo‘ja, Ajiniyoz, Berdaq",[[1225,1]],"uzlit"],
  ["Davlatmammad Ozodiy",[[1226,1]],"world"],
  ["Azim chinorlar",[[1227,1]],"uzlit"],
  ["Jaloliddin Rumiy, Yunus Emra, Ahmadiy",[[1228,1]],"world"],
  ["Jo‘shqin daryolar",[[1229,1]],"uzlit"],
  ["To‘lepbergen Qaipbergenov",[[1230,1]],"uzlit"],
  ["Ozarbayjon zamonaviy nasri antologiyasi",[[1231,1]],"world"],
  ["Yusuf Xos Hojib Ahmad Yugnakiy",[[1232,1]],"uzlit"],
  ["Saidazim Shirvoniy, Mirzo Aliakbar Sobir, Muhammad Hodiy",[[1233,1]],"world"],
  ["Berdi Kerboboyev, Qayum Tangriquliyev, Oraz Yag‘mur",[[1234,1]],"world"],
  ["Sobir Rustamxonli, Ramiz Ravshan",[[1235,1]],"world"],
  ["Xidir Deryayev",[[1236,1]],"world"],
  ["Nizomiy Ganjaviy",[[1237,1]],"world"],
  ["Yashar Kamol",[[1238,1]],"world"],
  ["Muxtor Avezov",[[1239,1]],"world"],
  ["Maxtumquli",[[1240,1]],"world"],
  ["Odil Yoqubov",[[1241,1]],"uzlit"],
  ["Omon Matjon",[[1242,1]],"uzlit"],
  ["Husayn Nihol Otsiz",[[1243,1]],"world"],
  ["Asqad Muxtor",[[1244,1]],"uzlit"],
  ["Venger adabiyoti namunalari",[[1245,1]],"world"],
  ["Qoraqalpoq zamonaviy she’riyati antologiyasi",[[1246,1]],"uzlit"],
  ["G‘abit Musrepov, Abish Kekilboyev",[[1247,1]],"world"],
  ["Mullanafas",[[1248,1]],"world"],
  ["Tugalboy Sidiqbekov",[[1249,1]],"world"],
  ["Turkman zamonaviy adabiyoti antologiyasi",[[1250,1]],"world"],
  ["Abdulla Qahhor, Mirkarim Osim, Said Ahmad",[[1251,1]],"uzlit"],
  ["Maqsud Shayxzoda",[[1252,1]],"uzlit"],
  ["Nomiq Kamol, Tavfiq Fikrat, Nozim Hikmat",[[1253,1]],"world"],
  ["Baxtiyor Vahobzoda, Xalil Rizo",[[1254,1]],"world"],
  ["O‘zbek zamonaviy she’riyati antologiyasi",[[1255,1]],"uzlit"],
  ["Aziz Nesin",[[1256,1]],"world"],
  ["Nurmuhammad Andalib, Mo‘llamurod Xorazmiy",[[1257,1]],"world"],
  ["Abdulla Qodiriy",[[1258,1]],"uzlit"],
  ["Tariq Bug‘ra",[[1259,1]],"world"],
  ["Zahiriddin Muhammad Bobur",[[1260,1]],"uzlit"],
  ["Ibroyim Yusupov",[[1261,1]],"uzlit"],
  ["Chingiz Aytmatov",[[1262,1]],"world"],
  ["Shukur Xolmirzayev",[[1263,1]],"uzlit"],
  ["Ижод богидан гулдаста",[[1264,2]],"uzlit"],
  ["Usmon Nosir",[[1265,1]],"uzlit"],
  ["So‘nmaydigan sadolar",[[1266,1]],"uzlit"],
  ["Qozoq zamonaviy nasri antologiyasi",[[1267,1]],"world"],
  ["Rashod Nuri Guntekin",[[1268,1]],"world"],
  ["Oltin avlod vakillari",[[1270,1]],"uzlit"],
  ["Umar Sayfiddin, Sabohiddin Ali",[[1271,1]],"world"],
  ["Jalil Mammadqulizoda, Yusuf Vazir Chamanzaminli",[[1272,1]],"world"],
  ["Ahmad Gunbay Yulduz, Ahmad Lutfi Qozonchi",[[1273,1]],"world"],
  ["Yusuf Samado‘g‘li",[[1274,1]],"world"],
  ["Qirg‘iz zamonaviy she’riyati antologiyasi",[[1275,1]],"world"],
  ["Nosiruddin Burhonuddin Rabg‘uziy",[[1276,1]],"uzlit"],
  ["Muqimiy, Furqat, Hamza",[[1277,1]],"uzlit"],
  ["O‘zbek mumtoz she’riyati antologiyasi",[[1278,1]],"uzlit"],
  ["Mirtemir",[[1279,1]],"uzlit"],
  ["Uvaysiy, Nodira",[[1280,1]],"uzlit"],
  ["O‘ljas Sulaymonov",[[1281,1]],"world"],
  ["Samad Vurg‘un",[[1282,1]],"world"],
  ["Abdulla Oripov",[[1283,1]],"uzlit"],
  ["Erkin Vohidov",[[1284,1]],"uzlit"],
  ["Rauf Parfi, Shavkat Rahmon",[[1285,1]],"uzlit"],
  ["Yangi zamon jarchilari",[[1286,1]],"uzlit"],
  ["Otajon Tog‘on",[[1287,1]],"world"],
  ["O‘tkir Hoshimov, Tog‘ay Murod",[[1288,1]],"uzlit"],
  ["Sazoyi Qoraqo‘ch, Jo‘shqin Qorabulut, Ali Oqbosh",[[1289,1]],"world"],
  ["Zamonidan o‘zganlar",[[1290,1]],"uzlit"],
  ["Mirza Ibrohimov",[[1291,1]],"world"],
  ["Qosim Sulaymonov, To‘lan Jo‘ldo‘shev",[[1292,1]],"world"],
  ["Muhammad Said O‘rdubodiy",[[1293,1]],"world"],
  ["O‘rxon Kamol, Suot Darvish",[[1294,1]],"world"],
  ["Mehmet O‘nder, Xayriddin Ivgin, Dundar Alp",[[1295,1]],"world"],
  ["Primqul Qodirov",[[1296,1]],"uzlit"],
  ["Muhammad Fuzuliy",[[1297,1]],"world"],
  ["Cho‘lpon",[[1298,1]],"uzlit"],
  ["Alisher Navoiy",[[1299,1]],"uzlit"],
  ["To‘lagan Qosimbekov",[[1300,1]],"world"],
  ["Sobit Muqonov, Qalmaqon Abduqodirov",[[1301,1]],"world"],
  ["Turk zamonaviy nasri antologiyasi",[[1302,1]],"world"],
  ["Ozarbayjon zamonaviy she’riyati antologiyasi",[[1303,1]],"world"],
  ["O‘zbek zamonaviy nasri antologiyasi",[[1304,1]],"uzlit"],
  ["Davlat boshqaruvi to‘g‘risida, 2-qism (Si Zinpin)",[[1305,1]],"society"],
  ["Davlat boshqaruvi to‘g‘risida, 1-qism (Si Zinpin)",[[1306,1]],"society"],
  ["O‘zbek Adabiyoti xazinasidan 4-jild Yusuf Xos Xojib Ahmad Yugnakiy",[[1307,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 5-jild Mahmud Koshg‘ariy",[[1308,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 6-jild Ahmad Yassaviy Sulaymon Boqirg‘oriy",[[1309,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 8-jild Nasiruddin Burhonuddin Rabg‘uziy",[[1310,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 12-jild Sakkokiy Atoyi",[[1311,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 13-jild Lutfiy Gadoiy",[[1312,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 15-jild Hofiz Xorazmiy",[[1313,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 21-jild Alisher Navoiy",[[1314,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 22-jild Alisher Navoiy",[[1315,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 24-jild Alisher Navoiy",[[1316,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 37-jild Shermuhammad Munis",[[1317,1]],"uzlit"],
  ["O‘zbek Adabiyoti xazinasidan 39-jild Muhammadrizo Ogahiy",[[1318,1]],"uzlit"],
  ["Jadidlar faoliyatida alifbo va imlo masalalari",[[1319,1]],"lang"],
  ["Ish yuritish terminlarining qisqacha izohli lug‘ati",[[1320,1]],"lang"],
  ["Xalqaro terminelementlarining qisqacha izohli-illyustrativ lug‘ati ( Lotin)",[[1321,1]],"lang"],
  ["Узбек тили синонимлари лугати",[[1322,1]],"lang"],
  ["Бир булсак ягона халкмиз, бирлашсак - Ватанмиз ( кирилл алифбосида)",[[1323,1]],"society"],
  ["ABC MURDERS_AGATHA CHRISTIE PB",[[1324,1]],"english"],
  ["AFTER FUNERAL_AGATHA CHRIST PB",[[1325,1]],"english"],
  ["BODY IN THE LIB",[[1326,1]],"english"],
  ["CHRISTIE READER - PADDINGTON",[[1327,1]],"english"],
  ["CHRISTIE READERS - APPOINTMENT",[[1328,1]],"english"],
  ["CHRISTIE READERS - CAT AMONG",[[1329,1]],"english"],
  ["CHRISTIE READERS - MIRRORS",[[1330,1]],"english"],
  ["CHRISTIE READERS - PERIL AT",[[1331,1]],"english"],
  ["CHRISTIE READERS - SPARKLING",[[1332,1]],"english"],
  ["CHRISTIE READERS - DESTINATION",[[1333,1]],"english"],
  ["EVIL UNDER SUN_AGATHA CHRIS PB",[[1334,1]],"english"],
  ["MAN IN BROWN SUIT_AGATHA CH PB",[[1335,1]],"english"],
  ["MIRROR CRACKD_AGATHA CHRIST",[[1336,1]],"english"],
  ["MOVING FINGER_AGATHA CHRIST PB",[[1337,1]],"english"],
  ["MURDER IS ANNOUNC_AGATHA CH PB",[[1338,1]],"english"],
  ["MURDER OF ROGER_AGATHA CHRI PB",[[1339,1]],"english"],
  ["THEN THERE",[[1340,1]],"english"],
  ["THEY CAME TO BAGHDAD ELT R PB",[[1341,1]],"english"],
  ["WHY DIDNT THEY_AGATHA CHRIS PB",[[1342,1]],"english"],
  ["WITNESS FOR THE",[[1343,1]],"english"],
  ["POIROT_BLACK COFFEE_ PB",[[1344,1]],"english"],
  ["POIROT_HERCULE",[[1345,1]],"english"],
  ["POIROT DEATH ON NILE PB",[[1346,1]],"english"],
  ["POIROT_MYSTERY OF THE BLUE_PB",[[1347,1]],"english"],
  ["POIROT_HALLOWEEN PARTY_ PB",[[1348,1]],"english"],
  ["POIROT_MURDER ON ORIENT_PB",[[1349,1]],"english"],
  ["POIROT_MURDER IN MESOPOTAMIA_",[[1350,1]],"english"],
  ["POIROT_BIG FOUR_ PB",[[1351,1]],"english"],
  ["POIROT_CARDS ON TABLE_ PB",[[1352,1]],"english"],
  ["POIROT_EVIL UNDER SUN_PB",[[1353,1]],"english"],
  ["POIROT_PERIL AT END HOUSE PB",[[1354,1]],"english"],
  ["POIROT_MURDER OF ROGER ACKRO",[[1355,1]],"english"],
  ["POIROT_SAD CYPRESS PB",[[1356,1]],"english"],
  ["POIROT_THREE ACT TRAGEDY_ PB",[[1357,1]],"english"],
  ["POIROT_MURDER ON LINKS_ PB",[[1358,1]],"english"],
  ["POIROT_DUMB WITNESS PB",[[1359,1]],"english"],
  ["POIROT_APPOINTMENT WITH_ PB",[[1360,1]],"english"],
  ["POIROT_ABC MURDERS_PB",[[1361,1]],"english"],
  ["POIROT_AFTER FUNERAL PB",[[1362,1]],"english"],
  ["PEAR Theseus and the Minotaur Bk/MP3 (1)",[[1363,1]],"english"],
  ["PEGR Ali and his Camera Bk/CD (1)",[[1364,1]],"english"],
  ["PEGR Battle of Newton Road Bk/CD (1)",[[1365,1]],"english"],
  ["PEGR Daniel Radcliffe Bk/CD (1)",[[1366,1]],"english"],
  ["PEGR Girl Meets Boy Bk/CD (1)",[[1367,1]],"english"],
  ["PEGR Five Famous Fairy Tales Bk/MP3 CD (2)",[[1368,1]],"english"],
  ["PEGR Five Plays for Today Bk/MP3 CD (2",[[1369,1]],"english"],
  ["PEGR Extreme Sports Bk/MP3 CD (2)",[[1370,1]],"english"],
  ["PEGR Mr Bean in Town Bk/MP3 CD (2)",[[1371,1]],"english"],
  ["PEGR Gandhi Bk/MP3 CD (2)",[[1372,1]],"english"],
  ["PEGR Black Beauty Bk/MP3 CD (2)",[[1373,1]],"english"],
  ["PEGR Barack Obama Bk/MP3 CD (2)",[[1374,1]],"english"],
  ["PEGR Audrey Hepburn Bk/MP3 CD (2)",[[1375,1]],"english"],
  ["PEGR Alice in Wonderland Bk/MP3 CD (2)",[[1376,1]],"english"],
  ["PEGR Last of the Mohicans Bk/MP3 CD (2)",[[1377,1]],"english"],
  ["PEGR Tales from Hans Andersen Bk/MP3 CD (2)",[[1378,1]],"english"],
  ["PEGR Mysterious Island Bk/MP3 CD (2)",[[1379,1]],"english"],
  ["PEGR Moby Dick Bk/MP3 CD (2)",[[1380,1]],"english"],
  ["PEGR King Arthur and the Knights of the Round Table Bk/MP3 CD (2)",[[1381,1]],"english"],
  ["PEGR Three Short Stories of Sherlock Holmes Bk/MP3 CD (2)",[[1382,1]],"english"],
  ["PEGR Voyages of Sindbad the Sailor Bk/MP3 CD (2)",[[1383,1]],"english"],
  ["PEGR Robinson Crusoe Bk/MP3 CD (2)",[[1384,1]],"english"],
  ["PEGR Pirates of the Caribbean: Curse of the Black Pearl Bk/MP3 CD (2)",[[1385,1]],"english"],
  ["PEGR Amazon Rainforest Book & MP3 Pck (2)",[[1386,1]],"english"],
  ["PEGR Robin Hood Bk/MP3 CD (2) OOP",[[1387,1]],"english"],
  ["PEGR Hamlet Bk/CD MP3 (3)",[[1388,1]],"english"],
  ["PEGR Turn of the Screw Bk/MP3 CD(3)",[[1389,1]],"english"],
  ["PEGR Stories from Shakespeare Bk/MP3 CD (3)",[[1390,1]],"english"],
  ["PEGR Cellist of Sarajevo Bk/MP3 CD (3)",[[1391,1]],"english"],
  ["PEGR Climb Bk/MP3 CD (3)",[[1392,1]],"english"],
  ["PEGR Canterbury Tales Bk/MP3 CD (3)",[[1393,1]],"english"],
  ["PEGR How to be an Alien Bk/MP3 CD (3)",[[1394,1]],"english"],
  ["PEGR Dr Jekyll & Hyde Bk/CD (6)",[[1395,1]],"english"],
  ["PEGR Braveheart Bk/MP3 CD (3)",[[1396,1]],"english"],
  ["PEGR Jungle Book Bk/MP3 CD (2)",[[1397,1]],"english"],
  ["PEAR Incredible Journey Bk/MP3 (3)",[[1398,1]],"english"],
  ["PEGR Black Cat and Other Stories Bk/MP3 CD (3)",[[1399,1]],"english"],
  ["PEGR Noughts and Crosses Bk/MP3 CD (3)",[[1400,1]],"english"],
  ["PEGR The Beatles Bk/MP3 CD (3)",[[1401,1]],"english"],
  ["PEGR Pirates of the Caribbean: Dead Man’s Chest Bk/MP3 CD (3)",[[1402,1]],"english"],
  ["PEGR No.1 Ladies Detective Agency Bk/MP3 CD (3)",[[1403,1]],"english"],
  ["PEGR Jim Smiley and His Jumping Frog Bk/MP3 CD (3)",[[1404,1]],"english"],
  ["PEGR:History of Britain Book & MP3 Pk (3)",[[1405,1]],"english"],
  ["PEGR Leaving Microsoft to Change the World Bk/MP3 CD (3)",[[1406,1]],"english"],
  ["PEGR Sherlock Holmes and the Mystery of Boscombe Pool Bk/MP3 CD (3)",[[1407,1]],"english"],
  ["PEGR Amistad Bk/MP3 CD (3)",[[1408,1]],"english"],
  ["PEGR Stories of Survival Bk/MP3 CD (3)",[[1409,1]],"english"],
  ["PEGR Island of Dr Moreau Bk/MP3 CD (3)",[[1410,1]],"english"],
  ["PEAR Charles Dickens Bk/MP3 (3)",[[1411,1]],"english"],
  ["PEGR Princess Diana Bk/MP3 CD (3)",[[1412,1]],"english"],
  ["PEGR Fall of the House of Usher and Other Stories Bk/MP3 CD (3)",[[1413,1]],"english"],
  ["PEGR Bourne Identity Bk/MP3 CD (4)",[[1414,1]],"english"],
  ["PEGR Alexander the Great Bk/MP3 CD (4)",[[1415,1]],"english"],
  ["PEGR Merchant of Venice Bk/MP3 CD (4)",[[1416,1]],"english"],
  ["PEGR Shakespeare - His Life and Plays Bk/MP3 CD (4)",[[1417,1]],"english"],
  ["PEGR Client Bk/MP3 CD (4)",[[1418,1]],"english"],
  ["PEGR Three Adventures of Sherlock Holmes Bk/MP3 CD (4)",[[1419,1]],"english"],
  ["PEGR King Solomons Mines Bk/MP3 CD (4)",[[1420,1]],"english"],
  ["PEGR Emma Bk/MP3 CD (4)",[[1421,1]],"english"],
  ["PEAR 1984 Bk/MP3 (2)",[[1422,1]],"english"],
  ["PEGR Evening Class Bk/MP3 CD (4)",[[1423,1]],"english"],
  ["PEGR Canterville Ghost and Other Stories Bk/MP3 CD (4)",[[1424,1]],"english"],
  ["PEGR Gone with the Wind 2 Bk (4)",[[1425,1]],"english"],
  ["PEGR Checkmate Bk/MP3 CD (4)",[[1426,1]],"english"],
  ["PEGR Time Machine Bk/MP3 CD (4)",[[1427,1]],"english"],
  ["PEGR Dr Faustus Bk/MP3 CD (4)",[[1428,1]],"english"],
  ["PEGR Doll’s House and Other Stories Bk/MP3 CD (4)",[[1429,1]],"english"],
  ["PEGR Brethren Bk/MP3 CD (5)",[[1430,1]],"english"],
  ["PEGR Hound of the Baskervilles Bk/MP3 CD (5)",[[1431,1]],"english"],
  ["PEGR Mayor of Casterbridge Bk/MP3 CD (5)",[[1432,1]],"english"],
  ["PEGR Sherlock Holmes Short Stories Bk/MP3 CD (5)",[[1433,1]],"english"],
  ["PEGR Cold Mountain Bk/MP3 CD (5)",[[1434,1]],"english"],
  ["PEGR Taste and Other Tales Bk/MP3 CD (5)",[[1435,1]],"english"],
  ["PEGR Five People You Meet in Heaven Bk/MP3 CD (5)",[[1436,1]],"english"],
  ["PEGR Outstanding Short Stories Bk/MP3 CD (5)",[[1437,1]],"english"],
  ["PEGR British and American Short Stories Bk/MP3 CD (5)",[[1438,1]],"english"],
  ["PEGR Citadel Bk/MP3 CD (5)",[[1439,1]],"english"],
  ["PEGR Tales from Shakespeare Bk/MP3 CD (5)",[[1440,1]],"english"],
  ["PEGR Tale of Two Cities Bk/MP3 CD (5)",[[1441,1]],"english"],
  ["PEGR War of the Worlds Bk/MP3 CD (5)",[[1442,1]],"english"],
  ["PEGR Jane Eyre Bk/MP3 CD (5)",[[1443,1]],"english"],
  ["PEGR Misery Bk/MP3 CD (6)",[[1444,1]],"english"],
  ["PEGR Beach Bk/MP3 CD (6)",[[1445,1]],"english"],
  ["PEGR Brave New World Bk/CD (6)",[[1446,1]],"english"],
  ["PEGR Captain Corelli’s Mandolin Bk/MP3 CD (6)",[[1447,1]],"english"],
  ["PEGR Man from the South and Other Stories Bk/MP3 CD (6)",[[1448,1]],"english"],
  ["PEGR Saving Private Ryan Bk/MP3 CD (6)",[[1449,1]],"english"],
  ["PEGR Crime and Punishment Bk/MP3 CD (6)",[[1450,1]],"english"],
  ["PEGR Anna Karenina Bk/MP3 CD(6)",[[1451,1]],"english"],
  ["PEGR Animal Farm Bk/CD (6)",[[1452,1]],"english"],
  ["Tales of the Greek Heroes",[[1453,1]],"english"],
  ["Grimms Fairy Tales",[[1454,1]],"english"],
  ["Sherlock Holmes",[[1455,1]],"english"],
  ["Surrounded by Idiots",[[1456,1]],"english"],
  ["HOW TO TALK TO ANYONE PB",[[1457,1]],"english"],
  ["The Circle",[[1458,1]],"english"],
  ["The Amazing Maurice and his Educated Rod",[[1459,1]],"english"],
  ["The Boy in the Striped Pyjamas",[[1460,1]],"english"],
  ["The Curious Incident of theDog in the N",[[1461,1]],"english"],
  ["Rowley Jeffersons AwesomeFriendly Spook",[[1462,1]],"english"],
  ["Rowley Jeffersons AwesomeFriendly Adven",[[1463,1]],"english"],
  ["Diary of an AwesomeFriendly Kid",[[1464,1]],"english"],
  ["Peter Pan",[[1465,1]],"english"],
  ["The Complete Short Novels",[[1466,1]],"english"],
  ["The Book Thief",[[1467,1]],"english"],
  ["The Girl in The Tower",[[1468,1]],"english"],
  ["The Winter of the Witch",[[1469,1]],"english"],
  ["The Bear and the Nightingale",[[1470,1]],"english"],
  ["Such Charming Liars",[[1471,1]],"english"],
  ["Unstoppable Us Volume 2",[[1472,1]],"english"],
  ["Unstoppable Us Volume 1",[[1473,1]],"english"],
  ["Tomorrow and Tomorrow and Tomorrow",[[1474,1]],"english"],
  ["The Last Devil To Die",[[1475,1]],"english"],
  ["The Catcher in the Rye",[[1476,1]],"english"],
  ["The Brothers Hawthorne",[[1477,1]],"english"],
  ["The Dinosaurs Diary",[[1478,1]],"english"],
  ["The Da Vinci Code",[[1479,1]],"english"],
  ["The Lost Symbol",[[1480,1]],"english"],
  ["RAMADAN KAREEM PB",[[1481,1]],"english"],
  ["The Classic Car Book",[[1482,1]],"english"],
  ["The Master and Margarita",[[1483,1]],"english"],
  ["The Idiot",[[1484,1]],"english"],
  ["The Penguin Book of Modern British Short",[[1485,1]],"english"],
  ["The Fault in Our Stars",[[1486,1]],"english"],
  ["The Book You Wish Your Parents Had Read",[[1487,1]],"english"],
  ["The Body Keeps the Score",[[1488,1]],"english"],
  ["Thinking Fast and Slow",[[1489,1]],"english"],
  ["The Little French Village ofBook Lovers",[[1490,1]],"english"],
  ["The Secret Life of Walter Mitty",[[1491,1]],"english"],
  ["The Bee Sting",[[1492,1]],"english"],
  ["There are Rivers in the Sky",[[1493,1]],"english"],
  ["The Box Man",[[1494,1]],"english"],
  ["The Inheritance Games",[[1495,1]],"english"],
  ["The Hawthorne Legacy",[[1496,1]],"english"],
  ["The Summer I Turned Pretty",[[1497,1]],"english"],
  ["The Thursday Murder Club",[[1498,1]],"english"],
  ["The Stories of Ray Bradbury",[[1499,1]],"english"],
  ["The Grandest Game",[[1500,1]],"english"],
  ["The Handmaids Tale",[[1501,1]],"english"],
  ["The Secret History",[[1502,1]],"english"],
  ["Roald Dahl 16 CopyComplete Collection",[[1503,1]],"english"],
  ["The Age of Dinosaurs: The Rise and",[[1504,1]],"english"],
  ["FLAT STANLEY_FLAT STANLEY",[[1505,1]],"english"],
  ["THE GIVER EMC FILM TIE-IN",[[1506,1]],"english"],
  ["Wonder",[[1507,1]],"english"],
  ["AUSTERE ACADEMY_SERIES OF U",[[1508,1]],"english"],
  ["GANGSTA GRANNY PB",[[1509,1]],"english"],
  ["GIANTS & JONESES PB",[[1510,1]],"english"],
  ["1-2-3 Scream!",[[1511,1]],"english"],
  ["RUNNING ON CRACKS PB",[[1512,1]],"english"],
  ["PEAR Nightmare Before Christmas Bk/MP3 (2)",[[1513,1]],"english"],
  ["Caraval Garber, Stephanie",[[1514,1]],"english"],
  ["Cinder (Repackaged Ed.) Meyer, Marissa",[[1515,1]],"english"],
  ["You’ve Reached Sam (Intl E Thao, Dustin",[[1516,1]],"english"],
  ["GALILEOS DREAM PB",[[1517,1]],"english"],
  ["RED MARS PB",[[1518,1]],"english"],
  ["BLUE MARS PB",[[1519,1]],"english"],
  ["Legendary",[[1520,1]],"english"],
  ["Kite Runner",[[1521,1]],"english"],
  ["And the Mountains Echoed OME",[[1522,1]],"english"],
  ["Thousand Splendid Suns OME",[[1523,1]],"english"],
  ["RAMONA QUIMBY AGE 8 PB",[[1524,1]],"english"],
  ["Sapiens",[[1525,1]],"english"],
  ["Homo Deus",[[1526,1]],"english"],
  ["Nexus",[[1527,1]],"english"],
  ["How to Sound Realy Clever",[[1528,1]],"english"],
  ["Football Legends Men’s 2025",[[1529,1]],"english"],
  ["WORLD OF FOOTBALL PB",[[1530,1]],"english"],
  ["POIROT-TAKEN AT THE FLOOD PB",[[1531,1]],"english"],
  ["Cambridge International AS & A Level Physics Coursebook with Digital Access (2 Years) 3ed",[[1532,30]],"cambridge"],
  ["Cambridge International AS & A Level Physics Workbook with Digital Access (2 Years)",[[1533,30]],"cambridge"],
  ["Cambridge International AS & A Level Physics Practical Workbook",[[1534,30]],"cambridge"],
  ["Cambridge International AS & A Level Physics Digital Teacher’s Resource Access Card",[[1535,1]],"cambridge"],
  ["Cambridge IGCSE™ Physics Coursebook with Digital Access (2 Years)",[[1536,24]],"cambridge"],
  ["Cambridge IGCSE™ Physics Workbook with Digital Access (2 Years)",[[1537,24]],"cambridge"],
  ["Cambridge IGCSE™ Physics Practical Workbook with Digital Access (2 Years)",[[1538,24]],"cambridge"],
  ["Cambridge IGCSE™ Chemistry Coursebook with Digital Access (2 Years)",[[1540,25]],"cambridge"],
  ["Cambridge IGCSE™ Chemistry Digital Teacher’s Resource Access Card",[[1541,1]],"cambridge"],
  ["Cambridge IGCSE™ Chemistry Workbook with Digital Access (2 Years)",[[1542,25]],"cambridge"],
  ["Cambridge IGCSE™ Chemistry Practical Workbook with Digital Access (2 Years)",[[1543,25]],"cambridge"],
  ["Cambridge International AS & A Level Chemistry Coursebook with Digital Access (2 Years)",[[1544,15]],"cambridge"],
  ["Cambridge International AS & A Level Chemistry Workbook with Digital Access (2 Years)",[[1545,15]],"cambridge"],
  ["Cambridge International AS & A Level Chemistry Digital Teacher’s Resource Access Card",[[1546,1]],"cambridge"],
  ["Cambridge IGCSE™ Biology Coursebook with Digital Access (2 Years)",[[1547,25]],"cambridge"],
  ["Cambridge IGCSE™ Biology Workbook with Digital Access (2 Years)",[[1548,25]],"cambridge"],
  ["Cambridge IGCSE™ Biology Practical Workbook with Digital Access (2 Years)",[[1549,25]],"cambridge"],
  ["Cambridge International AS & A Level Biology Coursebook with Digital Access (2 Years) 5ed",[[1551,15]],"cambridge"],
  ["Cambridge International AS & A Level Biology Workbook with Digital Access (2 Years)",[[1552,15]],"cambridge"],
  ["Cambridge International AS & A Level Biology Practical Workbook",[[1553,15]],"cambridge"],
  ["Cambridge International AS & A Level Biology Digital Teacher’s Resource Access Card",[[1554,2]],"cambridge"],
  ["Cambridge International AS & A Level Chemistry Practical workbook",[[1555,15]],"cambridge"],
  ["Sir Gawain and the Green Knight",[[1556,1]],"english"],
  ["PEGR I know Why the Caged Bird Sings Bk/MPЗ CD (6)",[[1557,1]],"english"],
  ["Хоразм немислари ёхуд.Окмасчит вайроналари изидан ( рус тили)",[[1558,5]],"history"],
  ["Хоразм немислари ёхуд.Окмасчит вайроналари изидан ( лотин )",[[1559,5]],"history"],
  ["Хоразм немислари ёхуд.Окмасчит вайроналари изидан ( инглиз )",[[1560,5]],"history"],
  ["Хоразм немислари ёхуд.Окмасчит вайроналари изидан ( кирил )",[[1561,5]],"history"],
  ["Alisher Navoiy asarlari",[[1562,31]],"uzlit"],
  ["Ijod bog‘idan guldasta 7 - son",[[1563,2]],"uzlit"],
  ["Во имя чести и достоинства человека, во имя благополучия народа ( рус)",[[1564,1]],"society"],
  ["Инсон кадри учун, эл-юрт фаровонлиги учун ( кирил)",[[1565,2]],"society"],
  ["Inson qadri uchun, Elyurt farovonligi uchun ( lotin)",[[1566,2]],"society"],
  ["Cambridge IGCSE English as a Second Language TEACHER’S RESOURCE with Digital Access",[[1567,4]],"cambridge"],
  ["Cambridge IGCSE English a Second Language COURSEBOOK with Digital Access",[[1568,50]],"cambridge"],
  ["Cambridge IGCSE English a Second Language WORKBOOK with Digital Access",[[1569,50]],"cambridge"]
];
/*</catalog>*/
/*<seedcode>*/
const SEED = 1;   // raise it when CATALOG grows: a library saved before that gets the new titles and copies added
/** Adds every title and copy of CATALOG that the library does not have yet. Nothing is changed or taken away, so running it again is harmless. */
function mergeCatalog(d) {
  if ((d.seed || 0) >= SEED) return d;
  const titleKey = (s) => String(s || '').toLowerCase().replace(/[\s'’‘`ʻʼ]/g, '');
  const numberKey = (s) => String(s || '').toLowerCase().replace(/[\s'’‘`ʻʼ\-_.\/№#]/g, '').replace(/к/g, 'k');
  const books = d.books.slice(), copies = d.copies.slice(), byTitle = new Map(), taken = new Set(copies.map((c) => numberKey(c.barcode)));
  books.forEach((b) => [b.enTitle, b.uzTitle].forEach((x) => { const k = titleKey(x); if (k && !byTitle.has(k)) byTitle.set(k, b); }));
  let bookId = books.reduce((n, b) => Math.max(n, b.id), 0), copyId = copies.reduce((n, c) => Math.max(n, c.id), 0);
  CATALOG.forEach(([title, rows, cat]) => {
    let b = byTitle.get(titleKey(title));
    if (!b) { b = { id: ++bookId, isbn: null, enTitle: title, enAuthor: '', uzTitle: title, uzAuthor: '', ...(cat ? { cat } : {}) }; books.push(b); byTitle.set(titleKey(title), b); }
    rows.forEach(([row, n]) => {
      for (let i = 1; i <= n; i++) {
        const barcode = `K${row}-${String(i).padStart(2, '0')}`, k = numberKey(barcode);
        if (!taken.has(k)) { taken.add(k); copies.push({ id: ++copyId, bookId: b.id, barcode, status: 'AVAILABLE', condition: 'GOOD', shelf: '' }); }
      }
    });
  });
  return { ...d, books, copies, seed: SEED };
}
const CAT_SEED = 1;   // raise it when the categories in CATALOG are revised: titles without a category then get theirs
/** Gives every title of the school's list its category, once. A category the librarian set or changed stays. */
function seedCats(d) {
  if ((d.catSeed || 0) >= CAT_SEED || !CATALOG.length) return d;
  const key = (s) => String(s || '').toLowerCase().replace(/[\s'’‘`ʻʼ]/g, ''), of = new Map();
  CATALOG.forEach(([title, , cat]) => { if (cat && !of.has(key(title))) of.set(key(title), cat); });
  const books = d.books.map((b) => (b.cat ? b : (() => { const c = of.get(key(b.enTitle)) || of.get(key(b.uzTitle)); return c ? { ...b, cat: c } : b; })()));
  return { ...d, books, catSeed: CAT_SEED };
}
const HOUSE_SEED = 1;   // raise it when the school sends a new list of houses: every listed student is then put into their house again
/** Puts the students on the school's house lists (ROSTER.houses) into their houses, once. What the librarian changes afterwards stays. */
function seedHouses(d) {
  if ((d.houseSeed || 0) >= HOUSE_SEED || !ROSTER.houses || !ROSTER.houses.length) return d;
  const of = new Map();
  ROSTER.houses.forEach(([house, names]) => names.forEach((name) => of.set(name, house)));
  const people = d.people.map((p) => (p.kind === 'student' && of.has(p.enName) && p.house !== of.get(p.enName) ? { ...p, house: of.get(p.enName) } : p));
  return { ...d, people, houseSeed: HOUSE_SEED };
}
/*</seedcode>*/
// The personal codes that were handed out on paper: reader number -> [code, name]. build-netlify.py copies them here from
// pins.json (kept outside the page, like this file). They are given to the listed people once: a library that has not
// had them yet (data.pinSeed) gets them on its next read, so the paper slips work from the first minute. After that
// the desk is in charge: a new code from the librarian stays.
/*<pins>*/
const PIN_SEED = 1;
const PINS = {"S-001":["875597","Allaberganova Xusniya"],"S-002":["982332","Amonboyev Fazliddin"],"S-003":["784087","Azimov Ulug‘bek"],"S-004":["361982","Bekpo‘latov A’zamjon"],"S-005":["472607","Durdibayev Temur"],"S-006":["395163","Egamberdiyev Shohjahon"],"S-007":["810882","Jumanazarov Shohjahon"],"S-008":["964567","Karimbayev Asrorbek"],"S-009":["103530","Kutlimuratov Muhammadmurod"],"S-010":["573145","Mametov Bobur"],"S-011":["597349","Matchonova Laziza"],"S-012":["804328","Matkarimov Azizbek"],"S-013":["332492","Maxsudov Shixnazar"],"S-014":["365658","Muxiddinov Bahodirjon"],"S-015":["713228","Otaboyev Aslbek"],"S-016":["362374","Palvannazirov Javohirbek"],"S-017":["141177","Po‘latova Aziza"],"S-018":["941671","Rahmanov Nurmuhammad"],"S-019":["107799","Saparbayeva Umida"],"S-020":["323134","Shamuratov Sadulla"],"S-021":["106576","Soburov Sarvarbek"],"S-022":["401778","Sultonbayev Mehrojbek"],"S-023":["256992","Sultonov Abror"],"S-024":["342839","Xolmurodov Suroj"],"S-025":["218182","Abdullayev Bunyodbek"],"S-026":["999874","Axmedov Rajabboy"],"S-027":["439725","Axmedov Sardorbek"],"S-028":["862110","Baxramov Musobek"],"S-029":["219325","Begnazarov Abdulaziz"],"S-030":["839380","Egamberganov Artur"],"S-031":["566157","Ermatov Kamronbek"],"S-032":["713046","Farxodov Abrorbek"],"S-033":["627514","Ismailov Iskandar"],"S-034":["133926","Janibekov Islombek"],"S-035":["267486","Kamilbayeva Dilnura"],"S-036":["964679","Kurbanbayev Asilbek"],"S-037":["752289","Kurbobayev Masharip"],"S-038":["492129","Nuroddinova Yulduz"],"S-039":["365700","Nurullayev Muhammadali"],"S-040":["416724","Ollaberganov Abduakbar"],"S-041":["107616","Ollaberganova Shahnoza"],"S-042":["420917","Otaxonova Munira"],"S-043":["758190","Rajabboyev Hojiakbar"],"S-044":["496572","Raxmatullayeva Shohina"],"S-045":["463924","Saidnazarova Dilfuza"],"S-046":["727611","Suvanova Hamida"],"S-047":["281166","Tuxtabayev Davud"],"S-048":["481657","Umarjonov Dovud"],"S-049":["730041","Abdullayev Azizbek"],"S-050":["511846","Ataxonov Akbarjon"],"S-051":["407303","Atayeva Barno"],"S-052":["271592","Azimov Boburbek"],"S-053":["117730","Baxtiyarov Abdulaziz"],"S-054":["641104","Baxtiyarov Elyor"],"S-055":["316096","Baxtiyorov Abdulaziz"],"S-056":["404840","Jumaboyev Nurali"],"S-057":["200633","Jumanazarov E’zozbek"],"S-058":["266719","Maqsudbekova Nilufar"],"S-059":["486442","Matyusupov Nurbek"],"S-060":["966436","Navruzov Nursulton"],"S-061":["172275","Otabekov Musobek"],"S-062":["893719","Qo‘chqarov Bilolbek"],"S-063":["986680","Rajabbayev Musobek"],"S-064":["474637","Raximov Rizobek"],"S-065":["308108","Sapayev Mustafo"],"S-066":["424400","Shanazarov Behruzbek"],"S-067":["672664","Shomurotov Mirjalol"],"S-068":["581552","Xamdamov Suhrobbek"],"S-069":["536665","Xursandov Feruzbek"],"S-070":["160493","Yangiboyeva Dilshoda"],"S-071":["131327","Yo‘ldashov Jonibek"],"S-072":["812073","Yusupboyeva Rahimajon"],"S-073":["146959","Abdullayev Jaloliddin"],"S-074":["921802","Alimbayev Salohiddin"],"S-075":["288564","Baxramov Umrbek"],"S-076":["462282","Baxtiyorova Zilola"],"S-077":["932688","Boxodirov Behruzbek"],"S-078":["206563","Ibadullayeva Zuhraxon"],"S-079":["890026","Jumaboyev Baxtiyor"],"S-080":["457705","Komilov Zafar"],"S-081":["840233","Maksudov Diyorbek"],"S-082":["769054","Maxsudov Polvonbek"],"S-083":["382297","Mirzakarimov Nodirbek"],"S-084":["822319","Niyozmetov Azizbek"],"S-085":["897156","Odilbekov Madaminbek"],"S-086":["686032","Otabekova Shaydo"],"S-087":["765228","O‘ktamboyev Mirjahon"],"S-088":["122652","Ravshanov Asilbek"],"S-089":["134194","Rustamov Behruzbek"],"S-090":["473346","Sadikov Hasanboy"],"S-091":["155775","Saparboyev Sardorbek"],"S-092":["385302","Sobirov Sobirjon"],"S-093":["353420","Sultannazarov Akbar"],"S-094":["257298","Urinbayeva Adiba"],"S-095":["182411","Xudayarov Doniyor"],"S-096":["527234","Xusinov Axrorbek"],"S-097":["263774","Atayev Zufar"],"S-098":["853640","Azamatov Alibek"],"S-099":["475966","Bahodirov Behruzbek"],"S-100":["986448","Bakdurdiyev Laziz"],"S-101":["199531","Dushamboev Shahjahon"],"S-102":["841090","Dushamov Ulug‘bek"],"S-103":["690494","Ergashboyev Yunusbek"],"S-104":["565391","Ergashboyeva Rayhonoy"],"S-105":["939090","Erkinov Muhammadamin"],"S-106":["364339","Kuryazov Javoxir"],"S-107":["322565","Masharipov Bekzod"],"S-108":["430112","Masharipova Mushtariy"],"S-109":["887955","Matchanov Javohir"],"S-110":["366562","Polvanazirova Nodiraxon"],"S-111":["361008","Rajabbayev Ibrat"],"S-112":["249852","Rajabboyeva Malika"],"S-113":["768933","Raximov Ne’matjon"],"S-114":["555149","Salayev Rasulbek"],"S-115":["280940","Sardorov Kamronbek"],"S-116":["695414","Shamilov Shohruh"],"S-117":["529308","Sultanbayev Akmal"],"S-118":["206259","Tuxtabayev Deniz"],"S-119":["451764","Ulug‘bekov Mironshox"],"S-120":["742045","Ulug‘bekova Mohira"],"S-121":["131156","Aminboeva Ruxshona"],"S-122":["230520","Bahodirova Mushtariybonu"],"S-123":["593776","Baxtiyarov Oybek"],"S-124":["723690","Bekmuratov Akbar"],"S-125":["833506","Davronbekov Bardiboy"],"S-126":["234627","Gul’matov Behruzbek"],"S-127":["632567","Ikromov Muhammadjon"],"S-128":["576388","Islomboev Bunyobek"],"S-129":["858944","Karimboyev Olloshukur"],"S-130":["243914","Komiljonova Shahrizoda"],"S-131":["618757","Ko‘palov Shohjahon"],"S-132":["262518","Matkarimov Odilbek"],"S-133":["841965","Otaboyev Islombek"],"S-134":["421125","Otaxonov Asadbek"],"S-135":["850976","Rustamov Nurazizbek"],"S-136":["486609","Saitjanov Abbos"],"S-137":["681779","Sa’dullayev Hasanboy"],"S-138":["252391","Sa’dullayev Husanboy"],"S-139":["118502","Shukurlayev Samadjon"],"S-140":["456538","Sobirova Guli"],"S-141":["216746","Sotimbaev Ibratbek"],"S-142":["997749","Taxirjanov Abdulaziz"],"S-143":["682655","Yangiboyeva Shahzoda"],"S-144":["216770","Yo‘ldoshev Abdulloh"],"S-145":["436851","Allaberganov Xudoybergan"],"S-146":["557503","Arslonbekov Dilmurod"],"S-147":["352256","Azadov Sanjarbek"],"S-148":["144258","Baxramov Kamronbek"],"S-149":["738312","Bobojonov O‘tkirbek"],"S-150":["448757","Duschanova Nigina"],"S-151":["469282","Iskandarov Shohruhbek"],"S-152":["934708","Komilov Javohir"],"S-153":["693928","Matmuratov Amirhon"],"S-154":["529041","Nazarov Rasulbek"],"S-155":["247125","Ozimboyev Abror"],"S-156":["394874","Ozodov Munisbek"],"S-157":["612778","O‘rozmatov Mirjalol"],"S-158":["165561","Radjapboyev Murodbek"],"S-159":["618082","Rajabboyev Shahriyor"],"S-160":["676050","Rajabov Sahriyor"],"S-161":["492544","Sadullayev Asadulloh"],"S-162":["675850","Sadullayev Jasurbek"],"S-163":["686753","Shoxnazarova Gulsanam"],"S-164":["147417","Ulug‘bekova Dinora"],"S-165":["466962","Xajiyev Xajiboy"],"S-166":["774405","Xamroyeva Nilufar"],"S-167":["551907","Xojayeva Shaxloxon"],"S-168":["602372","Yangiboeva Farangiz"],"T-01":["388715","Adolat Alimjanovna"],"T-02":["545798","Adolat Allaberganova"],"T-03":["817035","Atamurad Matnazarov"],"T-04":["439319","Bunyod Khalikberdiev"],"T-05":["843486","Clement Odera"],"T-06":["949985","Dilnoza Atadjanova"],"T-07":["724935","Donovan Solomons"],"T-08":["806169","Farhod Allaberganov"],"T-09":["267701","Farook Ali"],"T-10":["110813","Farrux Xakimov"],"T-11":["422441","Gavin Haschek"],"T-12":["332589","Hamza Otayev"],"T-13":["709342","Iqbola Ortiqova"],"T-14":["861194","Ivy Mogano"],"T-15":["610672","Ixtiyor Xudarganov"],"T-16":["950315","Jacinta Muriu"],"T-17":["566165","Kakai Wasula"],"T-18":["370188","Laila Botirova"],"T-19":["603981","Lobar Ismayilova"],"T-20":["362205","Madina Masharipova"],"T-21":["605933","Marxabo Davlatova"],"T-22":["534555","Maryanne Deguzman"],"T-23":["177946","Muyassar Maxsudovna"],"T-24":["561828","Muyassar Palvanova"],"T-25":["534672","Nargiza Khamraeva"],"T-26":["373856","Nilufar Babajanova"],"T-27":["966315","Nodirbek Xusinov"],"T-28":["520203","Otabek Ganjayev"],"T-29":["861360","Oybek Abdullayev"],"T-30":["200778","Paul Wangui"],"T-31":["611507","Ramazon Ruzimov"],"T-32":["115464","Rashid Rajapov"],"T-33":["617602","Reyno Abasolo"],"T-34":["144495","Sarvar Sharipov"],"T-35":["110430","Sattorbek Yo‘ldoshev"],"T-36":["286855","Sevara Norbaeva"],"T-37":["625214","Shahlo Ibragimova"],"T-38":["600255","Shirin Bayjanova"],"T-39":["860005","Shohruh Madrimov"],"T-40":["937117","Shohsura Shavkatova"],"T-41":["950248","Shoira Gulamova"],"T-42":["308512","Shujaat Khan"],"T-43":["989230","Silondiwe Mathebula"],"T-44":["626162","Soxiba Babanazarova"],"T-45":["239526","Stephan Safari"],"T-46":["127994","Vaisbek Atanazarov"],"T-47":["559110","Yullrich Cloete"],"T-48":["205272","Zafar Ismoilov"],"T-49":["826675","Zilola Raximberganova"]};
/*</pins>*/
function seedPins(d) {
  if ((d.pinSeed || 0) >= PIN_SEED) return d;
  const people = d.people.map((p) => { const given = PINS[p.no]; return given && given[1] === p.enName ? { ...p, pin: given[0] } : p; });   // the name must match too: a number is never enough
  return { ...d, people, pinSeed: PIN_SEED };
}
// The booking rules. The page uses the very same lines (build-netlify.py copies them), so the desk, a reader's
// browser and this server can never disagree about who is first in a queue or when a set-aside book lapses.
/*<holdcode>*/
const HOLD = { limit: 2, shelfDays: 3, perDay: 20, keepDays: 90, minDays: 1, maxDays: 60 };   // bookings one reader may have at a time; days a set-aside book waits; bookings one reader may make in a day; days a finished booking stays on record; the fewest and the most days a reader may ask to keep the book
const holdDay = (iso, n) => { const d = new Date(`${iso}T12:00:00Z`); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };
const holdLive = (r) => r.status === 'PENDING' || r.status === 'READY';
/** How long a reader asks to keep a book they book: a whole number of days within the limits, or 0 when none was given. */
const holdDays = (n) => (Number.isInteger(n) && n >= HOLD.minDays && n <= HOLD.maxDays ? n : 0);
/** A copy that is free goes to the first reader waiting for its title, counted from the day `from`; with nobody waiting it is back on the shelf. */
function holdRoute(d, copy, from) {
  const next = d.reservations.find((r) => r.bookId === copy.bookId && r.status === 'PENDING');
  if (!next) { copy.status = 'AVAILABLE'; return null; }
  Object.assign(next, { status: 'READY', copyId: copy.id, readyOn: from, holdExpiresOn: holdDay(from, HOLD.shelfDays) });
  copy.status = 'ON_HOLD';
  return next;
}
/** What only the calendar decides: a set-aside book nobody collected in time lapses and its copy moves on to the next reader. True when anything changed. */
function holdSweep(d, today) {
  let changed = false;
  for (let guard = 0; guard < 2000; guard++) {
    const late = d.reservations.find((r) => r.status === 'READY' && r.holdExpiresOn && r.holdExpiresOn < today);
    if (!late) break;
    late.status = 'EXPIRED'; changed = true;
    const copy = d.copies.find((c) => c.id === late.copyId);
    if (copy && copy.status === 'ON_HOLD') holdRoute(d, copy, holdDay(late.holdExpiresOn, 1));   // the next reader's days start the morning after
  }
  for (const r of d.reservations) {   // a reader in a queue while a copy stands free on the shelf: it is theirs
    if (r.status !== 'PENDING' || d.reservations.find((x) => x.bookId === r.bookId && x.status === 'PENDING') !== r) continue;
    const free = d.copies.find((c) => c.bookId === r.bookId && c.status === 'AVAILABLE');
    if (free) { holdRoute(d, free, today); changed = true; }
  }
  const old = holdDay(today, -HOLD.keepDays);   // bookings that ended long ago are dropped, so the list never grows without end
  for (let i = d.reservations.length - 1; i >= 0; i--) {
    const r = d.reservations[i];
    if (!holdLive(r) && r.day && r.day < old) { d.reservations.splice(i, 1); changed = true; }
  }
  return changed;
}
/** Why this reader cannot book this title today, or '' when they can. */
function holdProblem(d, personId, bookId, today) {
  const p = d.people.find((x) => x.id === personId), b = d.books.find((x) => x.id === bookId);
  if (!p || !b) return 'gone';
  if (p.active === false) return 'inactive';
  const mine = d.reservations.filter((r) => r.studentId === personId && holdLive(r));
  if (mine.some((r) => r.bookId === bookId)) return 'twice';
  const ofTitle = d.copies.filter((c) => c.bookId === bookId && c.status !== 'LOST' && c.status !== 'WITHDRAWN');
  if (!ofTitle.length) return 'none';
  const out = d.loans.filter((l) => l.studentId === personId && l.status === 'ACTIVE');
  if (out.some((l) => ofTitle.some((c) => c.id === l.copyId))) return 'has';
  if (out.some((l) => l.dueDate < today)) return 'overdue';
  if (mine.length >= HOLD.limit) return 'limit';
  if (d.reservations.filter((r) => r.studentId === personId && r.day === today).length >= HOLD.perDay) return 'often';   // booking and cancelling over and over
  return '';
}
/** Book a title. A copy on the shelf is set aside at once; otherwise the reader takes the next place in the queue. days: how long the reader would like to keep it. */
function holdPlace(d, personId, bookId, today, id, at, days) {
  const r = { id, bookId, studentId: personId, status: 'PENDING', copyId: null, holdExpiresOn: null, at, day: today };   // at: the moment; day: the school's date
  if (holdDays(days)) r.days = days;
  d.reservations.push(r);
  if (d.reservations.find((x) => x.bookId === bookId && x.status === 'PENDING') === r) {
    const free = d.copies.find((c) => c.bookId === bookId && c.status === 'AVAILABLE');
    if (free) holdRoute(d, free, today);
  }
  return r;
}
/** Give a booking up. A copy that was set aside goes to the next reader in the queue, or back on the shelf. */
function holdCancel(d, id, today) {
  const r = id && typeof id === 'object' ? id : d.reservations.find((x) => String(x.id) === String(id));
  if (!r || !holdLive(r)) return null;
  const wasReady = r.status === 'READY';
  r.status = 'CANCELLED';
  if (wasReady) { const copy = d.copies.find((c) => c.id === r.copyId); if (copy && copy.status === 'ON_HOLD') holdRoute(d, copy, today); }
  return r;
}
/*</holdcode>*/
/*<actcode>*/
// More days on a loan, reading set for a class, a reader's own goal and code, and the activity log. Like the booking rules,
// these lines work on plain library data, and build-netlify.py copies them word for word into the server part.
const ACT = { renewMax: 14, renewTimes: 2, goalMax: 20, keepDays: 30, logMax: 1500, assignMaxDays: 120, assignPerPerson: 60, feedDays: 30, likeMax: 6000, picChars: 120000 };   // most days a reader may ask for; renewals a loan may have; answered requests and past reading stay this many days
const actList = (d, k) => (Array.isArray(d[k]) ? d[k] : (d[k] = []));
/** One line in the activity log: when, who, what, and the two details. The oldest lines fall off the end. */
function logAdd(d, at, by, k, a, b) {
  const log = actList(d, 'log');
  log.push({ at, by: String(by || ''), k, a: String(a === undefined || a === null ? '' : a), b: String(b === undefined || b === null ? '' : b) });
  if (log.length > ACT.logMax) log.splice(0, log.length - ACT.logMax);
}
const actName = (d, personId) => { const p = d.people.find((x) => x.id === personId); return p ? `${p.enName}${p.no ? ` (${p.no})` : ''}` : ''; };
const actTitle = (d, bookId) => { const b = d.books.find((x) => x.id === bookId); return b ? b.enTitle : ''; };
const actLoanTitle = (d, loanId) => { const l = d.loans.find((x) => x.id === loanId), c = l && d.copies.find((x) => x.id === l.copyId); return c ? `${actTitle(d, c.bookId)} [${c.barcode}]` : ''; };
/** Why this reader cannot ask for more days on this loan today, or '' when they can. */
function renewProblem(d, personId, loanId, days, today) {
  const l = d.loans.find((x) => x.id === loanId && x.studentId === personId && x.status === 'ACTIVE');
  if (!l) return 'gone';
  if (!Number.isInteger(days) || days < 1 || days > ACT.renewMax) return 'bad';
  if (l.dueDate < today) return 'overdue';
  if ((l.renewals || 0) >= ACT.renewTimes) return 'used';
  if (actList(d, 'requests').some((r) => r.loanId === loanId && r.status === 'PENDING')) return 'asked';
  const c = d.copies.find((x) => x.id === l.copyId);
  if (c && d.reservations.some((r) => r.bookId === c.bookId && r.status === 'PENDING')) return 'queue';
  return '';
}
function renewAsk(d, personId, loanId, days, today, id, at) {
  const r = { id, kind: 'renew', loanId, studentId: personId, days, status: 'PENDING', at, day: today };
  actList(d, 'requests').push(r);
  return r;
}
/** The desk answers a request: yes moves the due date on by the days asked for (from today when the day has passed), no leaves the loan alone. */
function renewDecide(d, id, yes, today, at) {
  const r = actList(d, 'requests').find((x) => String(x.id) === String(id) && x.status === 'PENDING');
  if (!r) return null;
  const l = d.loans.find((x) => x.id === r.loanId && x.status === 'ACTIVE');
  if (yes && l) { l.dueDate = holdDay(l.dueDate > today ? l.dueDate : today, r.days); l.renewals = (l.renewals || 0) + 1; r.newDue = l.dueDate; }
  Object.assign(r, { status: yes && l ? 'APPROVED' : 'DECLINED', decidedAt: at, decidedOn: today });
  return r;
}
/** Why reading cannot be set like this, or ''. by: the teacher's id, or 0 for the desk. Classes are whole grades, as everywhere. */
function assignProblem(d, by, bookId, classes, from, to) {
  if (by) { const p = d.people.find((x) => x.id === by); if (!p || p.kind !== 'teacher' || p.active === false) return 'who'; }
  if (!d.books.some((b) => b.id === bookId)) return 'gone';
  if (!Array.isArray(classes) || !classes.length || classes.length > 12 || classes.some((c) => typeof c !== 'string' || !c || c.length > 10)) return 'bad';
  const date = /^\d{4}-\d{2}-\d{2}$/;
  if (typeof from !== 'string' || typeof to !== 'string' || !date.test(from) || !date.test(to) || to < from || holdDay(from, ACT.assignMaxDays) < to) return 'dates';
  if (actList(d, 'assignments').filter((a) => a.by === by).length >= ACT.assignPerPerson) return 'many';
  return '';
}
/** A code a reader may choose: six digits, not all the same and not a run such as 123456. Returns '' when it will do. */
function pinFault(code) {
  if (!/^\d{6}$/.test(code)) return 'digits';
  const ds = [...code].map(Number);
  return new Set(code).size === 1 || ds.every((x, i) => i === 0 || x - ds[i - 1] === 1) || ds.every((x, i) => i === 0 || ds[i - 1] - x === 1) ? 'easy' : '';
}
/** The loan a post in the reading feed is about, when there may be such a post: 'b12' = loan 12 was borrowed, 'f12' = it was read and returned.
    A reader who switched the feed off has no posts. */
function feedLoan(d, k) {
  if (typeof k !== 'string' || !/^[bf]\d{1,9}$/.test(k)) return null;
  const l = d.loans.find((x) => x.id === Number(k.slice(1)));
  if (!l || (k[0] === 'f' && l.status !== 'RETURNED')) return null;
  const p = d.people.find((x) => x.id === l.studentId);
  return p && !p.hide ? l : null;
}
/** One step by a signed-in reader (e = { kind, id, … }), done on the library and written in the log. Returns '' when done, or why not. */
function actApply(d, personId, e, today, at) {
  const who = actName(d, personId);
  if (e.kind === 'renew') {
    if (actList(d, 'requests').some((r) => String(r.id) === String(e.id))) return 'twice';
    const why = renewProblem(d, personId, e.loanId, e.days, today);
    if (why) return why;
    renewAsk(d, personId, e.loanId, e.days, today, e.id, at);
    logAdd(d, at, who, 'renew-ask', actLoanTitle(d, e.loanId), `+${e.days}`);
    return '';
  }
  if (e.kind === 'unrenew') {
    const list = actList(d, 'requests'), i = list.findIndex((r) => String(r.id) === String(e.id) && r.studentId === personId && r.status === 'PENDING');
    if (i < 0) return 'gone';
    logAdd(d, at, who, 'renew-drop', actLoanTitle(d, list[i].loanId), '');
    list.splice(i, 1);
    return '';
  }
  if (e.kind === 'holddays') {   // a reader changes how long they would like a book they have booked; their place in the queue stays
    const r = d.reservations.find((x) => String(x.id) === String(e.id) && x.studentId === personId && holdLive(x));
    if (!r) return 'gone';
    if (!holdDays(e.days)) return 'bad';
    r.days = e.days;
    logAdd(d, at, who, 'hold-days', actTitle(d, r.bookId), `${e.days} days`);
    return '';
  }
  if (e.kind === 'like') {   // a heart on a post, or taking it back; saying the same thing twice changes nothing
    const likes = actList(d, 'likes'), i = likes.findIndex((x) => x.k === e.k && x.by === personId);
    if (e.on === false) { if (i >= 0) likes.splice(i, 1); return ''; }
    if (!d.people.some((x) => x.id === personId) || !feedLoan(d, e.k)) return 'gone';
    if (i < 0) { likes.push({ k: e.k, by: personId }); if (likes.length > ACT.likeMax) likes.splice(0, likes.length - ACT.likeMax); }
    return '';
  }
  if (e.kind === 'pic') {   // a reader's profile picture: v says which stored picture it is, '' takes it away. Only a page running on its own keeps the picture itself here (local).
    const p = d.people.find((x) => x.id === personId), v = typeof e.v === 'string' ? e.v : null;
    if (!p || v === null) return 'bad';
    if (v && !/^[a-z0-9]{8,24}$/.test(v) && !(e.local === true && v.length <= ACT.picChars && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(v))) return 'bad';
    if (v) p.pic = v; else delete p.pic;
    d.picRev = (Number(d.picRev) || 0) + 1;
    logAdd(d, at, who, 'pic', '', v ? 'new' : 'removed');
    return '';
  }
  if (e.kind === 'feed') {   // a reader chooses whether their books are posted in the reading feed
    const p = d.people.find((x) => x.id === personId);
    if (!p) return 'bad';
    if (e.on === false) p.hide = true; else delete p.hide;
    return '';
  }
  if (e.kind === 'goal') {
    const p = d.people.find((x) => x.id === personId);
    if (!p || !Number.isInteger(e.n) || e.n < 1 || e.n > ACT.goalMax) return 'bad';
    p.goal = e.n;
    return '';
  }
  if (e.kind === 'assign') {
    if (actList(d, 'assignments').some((a) => String(a.id) === String(e.id))) return 'twice';
    const why = assignProblem(d, personId, e.bookId, e.classes, e.from, e.to);
    if (why) return why;
    actList(d, 'assignments').push({ id: e.id, bookId: e.bookId, classes: e.classes.slice(), from: e.from, to: e.to, label: String(e.label || '').slice(0, 20), by: personId, at });
    logAdd(d, at, who || 'Desk', 'assign', actTitle(d, e.bookId), `${e.classes.join(', ')} · ${e.from} – ${e.to}`);
    return '';
  }
  if (e.kind === 'unassign') {   // a teacher removes their own; the desk (personId 0) removes any
    const list = actList(d, 'assignments'), i = list.findIndex((a) => String(a.id) === String(e.id) && (!personId || a.by === personId));
    if (i < 0) return 'gone';
    logAdd(d, at, who || 'Desk', 'unassign', actTitle(d, list[i].bookId), list[i].classes.join(', '));
    list.splice(i, 1);
    return '';
  }
  if (e.kind === 'pin') {
    const p = d.people.find((x) => x.id === personId);
    if (!p || String(p.pin) !== String(e.old)) return 'wrong';
    const fault = pinFault(String(e.pin));
    if (fault) return fault;
    if (String(e.pin) === String(e.old)) return 'same';
    p.pin = String(e.pin);
    logAdd(d, at, who, 'pin-self', '', '');
    return '';
  }
  return 'bad';
}
/** What only the calendar decides: a request for a loan that has ended is dropped, and answered requests and reading whose dates have passed leave the record after a while. True when anything changed. */
function actSweep(d, today) {
  let changed = false;
  const old = holdDay(today, -ACT.keepDays), reqs = actList(d, 'requests'), set = actList(d, 'assignments');
  for (let i = reqs.length - 1; i >= 0; i--) {
    const r = reqs[i], l = d.loans.find((x) => x.id === r.loanId);
    if (r.status === 'PENDING' ? !l || l.status !== 'ACTIVE' : (r.decidedOn || r.day || '') < old) { reqs.splice(i, 1); changed = true; }
  }
  for (let i = set.length - 1; i >= 0; i--) if (set[i].to < old || !d.books.some((b) => b.id === set[i].bookId)) { set.splice(i, 1); changed = true; }
  const likes = actList(d, 'likes');
  if (likes.length) {   // a like goes when its post has left the feed, or the loan behind it is no longer there
    const gone = holdDay(today, -(ACT.feedDays + 5)), byId = new Map(d.loans.map((l) => [l.id, l]));
    for (let i = likes.length - 1; i >= 0; i--) {
      const k = String(likes[i].k || ''), l = byId.get(Number(k.slice(1))), when = l && (k[0] === 'f' ? l.returnedAt : l.issuedAt);
      if (!when || new Date(when).toISOString().slice(0, 10) < gone) { likes.splice(i, 1); changed = true; }
    }
  }
  return changed;
}
/*</actcode>*/
function startData() {
  const people = [];
  const add = (kind, no, name, cls) => people.push({ id: people.length + 1, kind, no, card: '', enName: name, uzName: name, cls, active: true, email: '' });
  ROSTER.classes.forEach(([cls, names]) => names.forEach((name) => add('student', `S-${String(people.length + 1).padStart(3, '0')}`, name, cls)));
  ROSTER.teachers.forEach((name, i) => add('teacher', `T-${String(i + 1).padStart(2, '0')}`, name, ''));
  return seedCats(seedHouses(seedPins(mergeCatalog({ people, books: [], copies: [], loans: [], reservations: [], nextLoanId: 1, seed: 0 }))));
}
/** The saved library, or the starting list while nothing has been saved yet. A saved library with nobody in it gets the people,
    and one saved before the school's books were added gets the books. Loans and everything typed in at the desk stay as they are. */
function withStart(doc) {
  if (!doc) return { rev: 0, data: { ...startData(), requests: [], assignments: [], likes: [], log: [] } };
  let data = doc.data;
  if (data.people.length === 0 && ROSTER.classes.length) data = { ...data, people: startData().people };
  data = seedCats(seedHouses(seedPins(mergeCatalog(data))));   // the books, the codes on the slips, the school's houses and the books' categories, each added once
  data.reservations.forEach((r, i) => { if (r.id === undefined || r.id === null) r.id = `o${i + 1}`; });   // reservations from an old backup get the same ids the page gives them
  MORE.forEach((k) => { if (!Array.isArray(data[k])) data[k] = []; });   // a library saved before these lists existed
  return data === doc.data ? doc : { ...doc, data };
}

// ---- the library document: { rev, savedAt, data: { people, books, copies, loans, reservations, requests, assignments, log, nextLoanId, seed }, journal }
// journal: one line per revision, newest last: { rev, op: 'reserve' | 'cancel' | 'act', … } for a reader's step, { rev, op: 'desk', by } for a desk save.
const LISTS = ['people', 'books', 'copies', 'loans', 'reservations'];
const validData = (d) => !!d && typeof d === 'object' && LISTS.every((k) => Array.isArray(d[k]));
const MORE = ['requests', 'assignments', 'likes', 'log'];   // lists added later: a library saved before them simply has none yet
const cleanData = (d) => ({ ...Object.fromEntries(LISTS.map((k) => [k, d[k]])), ...Object.fromEntries(MORE.map((k) => [k, Array.isArray(d[k]) ? d[k] : []])), nextLoanId: Number(d.nextLoanId) || 1, seed: Number(d.seed) || 0, pinSeed: Number(d.pinSeed) || 0, houseSeed: Number(d.houseSeed) || 0, catSeed: Number(d.catSeed) || 0, picRev: Number(d.picRev) || 0 });
/** What readers get: only the people who have borrowed, reserved or asked for something, with name, class and house, and no e-mail
    addresses or card codes. The activity log stays with the desk. Houses are given as sizes only: how many students each one has. */
function publicData(d) {
  const borrowers = new Set([...d.loans, ...d.reservations, ...(d.requests || [])].map((x) => x.studentId));
  const shown = ({ id, kind, no, enName, uzName, cls, active, goal, house, grad, hide }) => ({ id, kind, no, enName, uzName, cls, active, goal, house, grad, hide });   // nor which picture they have: that is for signed-in readers (see pics)   // never the code, the e-mail or the card
  const loan = ({ id, copyId, studentId, issuedAt, dueDate, returnedAt, status, renewals, daysLate, conditionIn, conditionOut }) => ({ id, copyId, studentId, issuedAt, dueDate, returnedAt, status, renewals, daysLate, ...(conditionIn === 'DAMAGED' && conditionOut !== 'DAMAGED' ? { pen: true } : {}) });   // no override reasons, fines or condition notes: only that points were taken off for damage
  const { log, ...rest } = d;
  const houses = {};
  const classes = {};   // and each class: the ranking shows every class with its size, not only the readers the page knows
  d.people.forEach((p) => { if (p.kind === 'student' && p.house && p.active !== false) houses[p.house] = (houses[p.house] || 0) + 1; });
  d.people.forEach((p) => { if (p.kind === 'student' && p.cls && p.active !== false) classes[p.cls] = (classes[p.cls] || 0) + 1; });
  return { ...rest, people: d.people.filter((p) => borrowers.has(p.id) || p.goal || p.hide).map(shown), loans: d.loans.map(loan), houses, classes };
}
/** The library as it stands today: holds nobody collected in time have lapsed. Nothing is saved by looking. */
function current(stored) {
  const doc = withStart(stored);
  holdSweep(doc.data, today());
  actSweep(doc.data, today());
  return doc;
}

async function read(req, url, s) {
  const full = url.searchParams.get('full') === '1', zip = url.searchParams.get('z') === '1', since = url.searchParams.get('since');
  if (full && !(await signedIn(req, s))) return json({ error: 'auth' }, 401);
  const doc = current(await s.get('doc', { type: 'json' })), rev = doc.rev;
  if (full) return since !== null && Number(since) === rev ? json({ app: 'library-circulation', rev, unchanged: true, full: true }) : json({ app: 'library-circulation', ver: SERVER_VER, rev, data: doc.data, full: true }, 200, {}, zip);
  const cache = { 'cache-control': 'public, max-age=0, must-revalidate', 'netlify-cdn-cache-control': `public, max-age=${PUBLIC_CACHE_SECONDS}` };
  if (since !== null && Number(since) === rev) return json({ app: 'library-circulation', rev, unchanged: true }, 200, cache);
  return json({ app: 'library-circulation', ver: SERVER_VER, rev, data: publicData(doc.data) }, 200, cache, zip);
}

/** The library as it was before today's first change, kept for 30 days. The copy is uploaded only when today's does not exist yet. */
async function keepSnapshot(s, doc) {
  const key = `snap-${today()}`;
  try {
    if (await s.getMetadata(key)) return;
    await s.setJSON(key, doc, { onlyIfNew: true });
    const old = `snap-${holdDay(today(), -30)}`, list = await s.list({ prefix: 'snap-' });
    for (const b of (list && list.blobs) || []) if (b.key < old) await s.delete(b.key);
  } catch (e) { console.error('snapshot failed:', e); }   // a safety copy must never stop a save
}

/** One step by a signed-in reader. It is applied to the newest library and saved; if someone else saved in the same instant, it is tried again. */
async function readerStep(req, url, s, step) {
  const zip = url.searchParams.get('z') === '1', key = await secret(s);
  let body = null; try { body = await req.json(); } catch (_) { /* not JSON */ }
  if (step === act && body && body.op === 'pin') {   // changing the code asks for the old one: its tries are counted like sign-in tries, so it cannot be guessed from an open session
    const who = /^Reader (\d{1,9})\./.exec(req.headers.get('authorization') || '');
    const wait = who ? await countTry(s, `rpin-${who[1]}`, LIMITS.who, Date.now()) : 0;
    if (wait) return json({ error: 'wait', wait }, 429);
  }
  for (let attempt = 0; attempt < 6; attempt++) {
    const cur = await s.getWithMetadata('doc', { type: 'json' });
    const stored = cur ? cur.data : null, doc = withStart(stored), data = doc.data, day = today(), rev = doc.rev + 1;
    const me = readerOf(req, data, key);
    if (!me) return json({ error: 'auth' }, 401);
    if (stored && attempt === 0) await keepSnapshot(s, stored);   // before anything changes
    holdSweep(data, day); actSweep(data, day);
    const done = step(data, me, body || {}, day, rev);
    if (done.error) return json({ error: done.error }, done.error === 'bad' ? 400 : 409);
    const savedAt = new Date().toISOString();
    const next = { rev, savedAt, data: cleanData(data), journal: [...((stored && stored.journal) || []), { rev, at: savedAt, ...done.entry }].slice(-JOURNAL) };
    const put = await s.setJSON('doc', next, cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true });
    if (!put || put.modified !== false) {
      const fresh = {};
      if (done.newToken) { fresh.exp = Date.now() + READER_DAYS * 24 * 3600 * 1000; fresh.token = `${me.id}.${fresh.exp}.${readerSign(me, fresh.exp, key)}`; }   // the code is part of the sign-in: this device carries on with the new one
      if (done.entry && done.entry.op === 'act' && done.entry.kind === 'pic') await dropPics(s, me.id, done.entry.v);   // the pictures this reader had before are deleted
      if (body && body.light === true && !done.newToken) return json({ app: 'library-circulation', rev, light: true });   // a like: the page already shows it and needs no copy of the library back
      return json({ app: 'library-circulation', ver: SERVER_VER, rev, data: publicData(next.data), hold: done.hold || null, ...fresh }, 200, {}, zip);
    }
  }
  return json({ error: 'busy' }, 503);
}
const reserve = (d, me, body, day, rev) => {
  const bookId = Number(body.bookId);
  if (!Number.isInteger(bookId)) return { error: 'bad' };
  const asked = body.days !== undefined && body.days !== null, days = asked ? Number(body.days) : 0;   // how long the reader would like the book; a page from before this was added sends none
  if (asked && !holdDays(days)) return { error: 'bad' };
  const problem = holdProblem(d, me.id, bookId, day);
  if (problem) return { error: problem };
  const id = `h${rev}-${randomBytes(3).toString('hex')}`, at = new Date().toISOString(), r = holdPlace(d, me.id, bookId, day, id, at, days);
  logAdd(d, at, actName(d, me.id), 'reserve', actTitle(d, bookId), `${r.status === 'READY' ? 'set aside' : 'queue'}${r.days ? ` · ${r.days} days` : ''}`);
  return { entry: { op: 'reserve', id, personId: me.id, bookId, ...(r.days ? { days: r.days } : {}) }, hold: { id, status: r.status, holdExpiresOn: r.holdExpiresOn, days: r.days || 0 } };
};
const unreserve = (d, me, body, day) => {
  const r = d.reservations.find((x) => String(x.id) === String(body.id) && x.studentId === me.id);
  if (!r || !holdLive(r)) return { error: 'gone' };
  holdCancel(d, r, day);   // this very reservation, found by id AND owner
  logAdd(d, new Date().toISOString(), actName(d, me.id), 'hold-cancel', actTitle(d, r.bookId), '');
  return { entry: { op: 'cancel', id: r.id, personId: me.id }, hold: { id: r.id, status: r.status } };
};
/** Everything else a signed-in reader may do: more days on a loan, a goal, their own code; for a teacher, reading for classes.
    What may be asked, and by whom, is decided in actApply, the same lines the page uses. */
const ACT_KINDS = ['renew', 'unrenew', 'goal', 'assign', 'unassign', 'pin', 'holddays', 'like', 'feed', 'pic'];
const act = (d, me, body, day, rev) => {
  const kind = String(body.op || '');
  if (!ACT_KINDS.includes(kind)) return { error: 'bad' };
  const e = { kind, id: kind === 'renew' || kind === 'assign' ? `a${rev}-${randomBytes(3).toString('hex')}` : String(body.id || '').slice(0, 40) };
  if (kind === 'renew') Object.assign(e, { loanId: Number(body.loanId), days: Number(body.days) });
  if (kind === 'goal') e.n = Number(body.n);
  if (kind === 'holddays') e.days = Number(body.days);
  if (kind === 'like') Object.assign(e, { k: String(body.k || '').slice(0, 12), on: body.on !== false });
  if (kind === 'feed') e.on = body.on !== false;
  if (kind === 'pic') e.v = typeof body.v === 'string' ? body.v.slice(0, 24) : '';   // only ever the name of a stored picture, never a picture
  if (kind === 'assign') Object.assign(e, { bookId: Number(body.bookId), classes: Array.isArray(body.classes) ? body.classes.slice(0, 12).map((c) => String(c).slice(0, 10)) : null, from: body.from, to: body.to, label: String(body.label || '').slice(0, 20) });
  if (kind === 'pin') Object.assign(e, { old: String(body.old || '').replace(/\D/g, '').slice(0, 12), pin: String(body.pin || '').replace(/\D/g, '').slice(0, 12) });
  const why = actApply(d, me.id, e, day, new Date().toISOString());
  if (why) return { error: why };
  return { entry: { op: 'act', personId: me.id, ...e }, newToken: kind === 'pin' };
};
/** Do the readers' steps again on a copy of the library that was saved without them. A step that no longer makes sense is left out. */
function replay(d, steps, day) {
  holdSweep(d, day);
  for (const e of steps) {
    if (e.op === 'reserve') {
      if (d.reservations.some((r) => String(r.id) === String(e.id))) continue;
      if (['gone', 'inactive', 'twice', 'none', 'has'].includes(holdProblem(d, e.personId, e.bookId, day))) continue;
      const r = holdPlace(d, e.personId, e.bookId, day, e.id, e.at, e.days);
      logAdd(d, e.at, actName(d, e.personId), 'reserve', actTitle(d, e.bookId), `${r.status === 'READY' ? 'set aside' : 'queue'}${r.days ? ` · ${r.days} days` : ''}`);
    } else if (e.op === 'cancel') {
      const r = d.reservations.find((x) => String(x.id) === String(e.id) && x.studentId === e.personId);
      if (r && holdCancel(d, r, day)) logAdd(d, e.at, actName(d, e.personId), 'hold-cancel', actTitle(d, r.bookId), '');
    } else if (e.op === 'act') actApply(d, e.personId, e, day, e.at);   // refuses by itself what no longer makes sense
  }
  holdSweep(d, day); actSweep(d, day);
  if (Array.isArray(d.log)) d.log.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));   // the readers' lines go back to their place in time
}

async function write(req, url, s) {
  if (!(await signedIn(req, s))) return json({ error: 'auth' }, 401);
  const zip = url.searchParams.get('z') === '1';
  let text = '';
  if ((req.headers.get('content-type') || '').includes('gzip')) {   // the page packed the library before sending it
    const buf = Buffer.from(await req.arrayBuffer());
    if (buf.length > MAX_BYTES) return json({ error: 'too-big' }, 413);
    try { text = gunzipSync(buf, { maxOutputLength: MAX_BYTES + 1 }).toString('utf8'); }
    catch (e) { return e && e.code === 'ERR_BUFFER_TOO_LARGE' ? json({ error: 'too-big' }, 413) : json({ error: 'bad-gzip' }, 400); }
  } else text = await req.text();
  if (text.length > MAX_BYTES) return json({ error: 'too-big' }, 413);
  let body = null; try { body = JSON.parse(text); } catch (_) { /* not JSON */ }
  if (!body || !validData(body.data)) return json({ error: 'bad-data' }, 400);
  const by = (req.headers.get('x-desk') || '').slice(0, 40);              // which open desk page is saving
  const seq = Number(req.headers.get('x-desk-seq')) || 0;                 // and which of its saves this is
  const conflict = (d) => json({ error: 'conflict', rev: d ? d.rev : 0, data: d ? current(d).data : null }, 409, {}, zip);
  for (let attempt = 0; attempt < 4; attempt++) {
    const stored = await s.getWithMetadata('doc', { type: 'json' });
    const doc = stored ? stored.data : null, rev = doc ? doc.rev : 0, base = Number(body.rev) || 0, journal = (doc && doc.journal) || [];
    const data = cleanData(body.data);
    // A save that was given up on (a slow line) can still arrive after the newer one that replaced it. It must not win.
    const mine = by ? journal.filter((e) => e.op === 'desk' && e.by === by).pop() : null;
    if (mine && seq && mine.seq && seq <= mine.seq) return conflict(doc);
    let merged = false;
    if (base !== rev) {
      // The desk saved a copy that is some revisions old. That is fine when every revision since was a reader's step
      // (done again below, on the desk's copy) or this same desk's own earlier save (already inside its copy).
      const since = journal.filter((e) => e.rev > base);
      const mergeable = base < rev && since.length === rev - base && since.every((e) => e.op !== 'desk' || (by && e.by === by));
      if (!mergeable) return conflict(doc);                               // another desk saved first
      replay(data, since.filter((e) => e.op !== 'desk'), today());
      merged = true;
    } else { const a = holdSweep(data, today()), b = actSweep(data, today()); if (a || b) merged = true; }   // e.g. new copies of a title someone is queued for: the desk gets the result back
    if (doc && attempt === 0) await keepSnapshot(s, doc);
    const savedAt = new Date().toISOString();
    const next = { rev: rev + 1, savedAt, data, journal: [...journal, { rev: rev + 1, at: savedAt, op: 'desk', by, seq }].slice(-JOURNAL) };
    const done = await s.setJSON('doc', next, stored ? { onlyIfMatch: stored.etag } : { onlyIfNew: true });
    if (done && done.modified === false) continue;                        // someone saved in the same instant: look again
    return merged ? json({ rev: next.rev, savedAt, merged: true, data }, 200, {}, zip) : json({ rev: next.rev, savedAt });
  }
  return json({ error: 'busy' }, 503);                                    // lost the race four times: the page keeps the change and sends it again
}

/** Cover pictures live beside the library, one small JPEG per book, so the library itself stays light. A book remembers only the
    version of its picture (book.cover), which is part of the address, so a browser may keep a picture for good. */
async function cover(req, url, s) {
  const id = Number(url.searchParams.get('id'));
  if (!Number.isInteger(id) || id < 1) return json({ error: 'bad' }, 400);
  if (req.method === 'GET') {
    const img = await s.get(`cover-${id}`, { type: 'arrayBuffer' });
    if (!img || !img.byteLength) return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });   // no picture (not a 404: Netlify would answer that one with something else)
    return new Response(img, { headers: { 'content-type': 'image/jpeg', 'cache-control': 'public, max-age=31536000, immutable', 'x-content-type-options': 'nosniff' } });
  }
  if (req.method !== 'PUT') return json({ error: 'method' }, 405);
  if (!(await signedIn(req, s))) return json({ error: 'auth' }, 401);
  const buf = Buffer.from(await req.arrayBuffer());
  if (!buf.length) { await s.delete(`cover-${id}`); return json({ cover: '' }); }
  if (buf.length > COVER_BYTES || buf[0] !== 0xFF || buf[1] !== 0xD8) return json({ error: 'bad-image' }, 400);   // a JPEG, as the page makes it
  await s.set(`cover-${id}`, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length));
  return json({ cover: Date.now().toString(36) });
}

// ---- profile pictures: one small JPEG per reader, kept apart from the library under a name nobody can guess.
const PIC_TRIES = { free: 8, wait: () => 900, window: 3600 * 1000 };   // eight new pictures an hour, then one every quarter of an hour
const picName = (v) => typeof v === 'string' && /^[a-z0-9]{8,24}$/.test(v);
/** Delete every stored picture of this reader except the one to keep. */
async function dropPics(s, id, keep) {
  try {
    const list = await s.list({ prefix: `avatar-${id}-` });
    for (const b of (list && list.blobs) || []) if (b.key !== `avatar-${id}-${keep}`) await s.delete(b.key);
  } catch (e) { console.error('picture clean-up failed:', e); }
}
async function avatar(req, url, s) {
  const id = Number(url.searchParams.get('id'));
  if (req.method === 'GET') {
    const v = url.searchParams.get('v');
    if (!Number.isInteger(id) || id < 1 || !picName(v)) return json({ error: 'bad' }, 400);
    const img = await s.get(`avatar-${id}-${v}`, { type: 'arrayBuffer' });
    if (!img || !img.byteLength) return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    return new Response(img, { headers: { 'content-type': 'image/jpeg', 'cache-control': 'private, max-age=31536000, immutable', 'x-content-type-options': 'nosniff' } });
  }
  if (req.method !== 'PUT') return json({ error: 'method' }, 405);
  if (url.searchParams.has('id')) {   // the librarian takes a reader's picture away (the page then saves the library without it)
    if (!(await signedIn(req, s))) return json({ error: 'auth' }, 401);
    if (!Number.isInteger(id) || id < 1) return json({ error: 'bad' }, 400);
    await dropPics(s, id, '');
    return json({ ok: true });
  }
  const me = readerOf(req, withStart(await s.get('doc', { type: 'json' })).data, await secret(s));
  if (!me) return json({ error: 'auth' }, 401);
  const wait = await countTry(s, `pic-${me.id}`, PIC_TRIES, Date.now());
  if (wait) return json({ error: 'wait', wait }, 429);
  const buf = Buffer.from(await req.arrayBuffer());
  if (!buf.length || buf.length > AVATAR_BYTES || buf[0] !== 0xFF || buf[1] !== 0xD8 || buf[2] !== 0xFF) return json({ error: 'bad-image' }, 400);   // a JPEG, as the page makes it
  const v = randomBytes(8).toString('hex');
  await s.set(`avatar-${me.id}-${v}`, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length));
  return json({ v });
}
/** Which picture each reader has: for signed-in readers and the desk only, so the public library gives no way to a face. */
async function picsList(req, s) {
  if (req.method !== 'GET') return json({ error: 'method' }, 405);
  const d = withStart(await s.get('doc', { type: 'json' })).data;
  if (!readerOf(req, d, await secret(s)) && !(await signedIn(req, s))) return json({ error: 'auth' }, 401);
  const pics = {};
  d.people.forEach((p) => { if (picName(p.pic) && p.active !== false) pics[p.id] = p.pic; });
  return json({ rev: Number(d.picRev) || 0, pics }, 200, { 'cache-control': 'no-store' });
}

export default async (req, context) => {
  try {
    const url = new URL(req.url), s = store();
    const post = (run) => (req.method === 'POST' ? run() : json({ error: 'method' }, 405));
    if (url.pathname.endsWith('/reader/login')) return await post(() => readerLogin(req, context, s));
    if (url.pathname.endsWith('/cover')) return await cover(req, url, s);
    if (url.pathname.endsWith('/avatar')) return await avatar(req, url, s);
    if (url.pathname.endsWith('/pics')) return await picsList(req, s);
    if (url.pathname.endsWith('/act')) return await post(() => readerStep(req, url, s, act));
    if (url.pathname.endsWith('/unreserve')) return await post(() => readerStep(req, url, s, unreserve));
    if (url.pathname.endsWith('/reserve')) return await post(() => readerStep(req, url, s, reserve));
    if (url.pathname.endsWith('/login')) return await post(() => login(req, context, s));
    if (req.method === 'GET') return await read(req, url, s);
    if (req.method === 'PUT') return await write(req, url, s);
    return json({ error: 'method' }, 405);
  } catch (e) {
    console.error('library function failed:', e);
    return json({ error: 'server' }, 500);
  }
};

export const config = { path: ['/api/library', '/api/library/login', '/api/library/reader/login', '/api/library/reserve', '/api/library/unreserve', '/api/library/act', '/api/library/cover', '/api/library/avatar', '/api/library/pics'] };
