# HANDOFF — web-chat (ვებ-ჩატი ადმინ პანელით)

## რა არის

მარტივი ვებ-ჩატი Cloudflare Worker + D1-ზე, შაოს სპეციფიკაციით:
მხოლოდ username + პაროლი, მომხმარებლების პოვნა username-ით, 1:1 და
ჯგუფური ჩატები სათაურით, ადმინ პანელში ყველა ჩატი სათაურით
(წევრები + შეტყობინებების რაოდენობა + შესვლა) და ყველა მომხმარებელი.
პირველი დარეგისტრირებული მომხმარებელი ავტომატურად ადმინი ხდება.
მუქი თემა, ქართული ინტერფეისი, ერთი თვითკმარი HTML გვერდი.

## ფაილები (`~/workspace/web-chat/`)

- `wrangler.toml` — Worker `web-chat`, D1 binding `CHAT_DB`,
  `database_id` = `REPLACE_WITH_YOUR_D1_DATABASE_ID` (შაომ უნდა
  ჩასვას ნამდვილი id D1-ის შექმნის შემდეგ).
- `src/index.js` — მთელი Worker-ი (~1100 ხაზი): lazy idempotent
  სქემა v1 (users/sessions/rate_limits) → v2 (chats/chat_members)
  → v3 (messages + ინდექსები); PBKDF2-SHA256 hash (100k იტერაცია,
  თითო მომხმარებელზე ცალკე მარილი); DB-ში შენახული სესიები
  (SESSION_SECRET-ით pepper-იანი ტოკენის hash, cookie HttpOnly +
  Secure + SameSite=Lax, 30 დღე); IP-hash rate limiting;
  Origin-ის შემოწმება მუტაციურ API-ებზე; ჩატის UI.
- `schema.sql` — სრული D1 სქემა საცნობაროდ (წყარო: ensureSchema()).
- `test/chat-harness.mjs` — D1 mock `node:sqlite`-ზე.
- `README.md` — ქართული, დაყენების ნაბიჯებით.

## შემოწმება (2026-11-23, ლოკალურად)

- `node --check src/index.js` — OK.
- `node test/chat-harness.mjs` — **103 passed / 0 failed**.
  გავლილია: რეგისტრაცია/ლოგინი, hash-ის შემოწმება (არა უბრალო
  ტექსტი, სხვადასხვა მარილი = სხვადასხვა hash), ძებნა, 1:1 +
  ჯგუფური ჩატები, შეტყობინებები + `after=` polling + წაუკითხავი,
  ადმინის მიმოხილვა + ჩატში შესვლა, logout, Origin, rate limit-ები.
- ერთი ხარვეზი აღმოჩნდა და გასწორდა: v1 მიგრაცია ცარიელ ბაზაზე
  `schema_meta`-ს SELECT-ზე ეცემოდა (stock-ის პატერნით გასწორდა —
  flag-ის წაკითხვა try/catch-ში, მიგრაცია მის გარეთ).
- ერთი ტესტის მოლოდინი გასწორდა: გაგზავნა ჩატს წაკითხულად ნიშნავს
  (გამგზავნის unread 0 ხდება) — ეს სწორი ქცევაა.

## რა დარჩა შაოსგან (სანამ live გახდება)

1. GitHub-ზე ახალი საჯარო რეპოს შექმნა (მაგ. `web-chat`) და ამ
   საქაღალდის ატვირთვა. GitHub App-ს რეპოს შექმნა არ შეუძლია.
2. Cloudflare-ში D1 `web-chat-db`-ის შექმნა და `database_id`-ის
   ჩასმა `wrangler.toml`-ში.
3. Worker-ის დაკავშირება Git-თან (Workers & Pages → Connect to Git).
4. `SESSION_SECRET`-ის დაყენება Worker-ის Variables and Secrets-ში.
5. Deploy → პირველი რეგისტრაცია = შაო (ადმინი) → live-შემოწმება.

## შენიშვნები

- Deploy, wrangler login და GitHub ქმედებები არ გაკეთებულა (აკრძალული
  იყო დავალებით). ლოკალური შემოწმება მხოლოდ.
- Username: მხოლოდ ლათინური ასოები/ციფრები/`_`, 3–30 სიმბოლო,
  case-insensitive (Nika = nika).
- შეტყობინებები არ არის დაშიფრული (ეს №8 დაშიფრული ჩატის აპისგან
  განსხვავებული, მარტივი ვებ-ჩატია — იდეა №25).
- საჯარო ვერსია = სწორედ ეს Worker-ი (საჯარო workers.dev მისამართი);
  ცალკე „საჯაროდ გატანის" ნაბიჯი არ სჭირდება Deploy-ის შემდეგ.
