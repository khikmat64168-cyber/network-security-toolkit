# NST deploy jarayoni: boshidan oxirigacha

Bu hujjat Network Security Toolkit (NST) internetga qanday chiqarilganini,
qanday qarorlar qabul qilinganini, yo'lda qanday muammolar chiqib, qanday
hal qilinganini va endi yangi versiya qanday chiqarilishini tushuntiradi.

Qisqa buyruqlar to'plami (runbook) uchun: [README.md](README.md).

---

## 1. Natija

| Qism | Manzil | Kim uchun |
|---|---|---|
| Public demo | https://scannetwork.io (va `www`) | Hamma uchun: TLS sertifikat tekshiruvi va GeoIP |
| Maxfiy konsol | `http://127.0.0.1:8765` (faqat SSH tunnel orqali) | Faqat egasi: serverning o'z trafigini kuzatish |
| Python paket | GitHub Releases'dagi wheel | O'z kompyuterida to'liq ishlatmoqchi bo'lganlar |
| Docker image | `ghcr.io/khikmat64168-cyber/network-security-toolkit` | Coolify va maxfiy konsol |

Yangi versiya chiqarish bitta `git tag` va `git push` bilan bajariladi.
Testlar, image, reliz va ikkala deploy avtomatik ishlaydi.

---

## 2. Arxitektura

```
                     Internet
                        │  HTTPS (443)
                        ▼
        ┌──────────── VPS (Hostinger KVM 2, Ubuntu 24.04) ────────────┐
        │                                                             │
        │  Traefik (Coolify)  ── Let's Encrypt sertifikat             │
        │        │                                                    │
        │        ▼  coolify docker tarmog'i                           │
        │  nst-public konteyner :8766                                 │
        │    NST_WEB_MODE=public, uid 10001, --cap-drop ALL           │
        │    TLS + GeoIP, rate-limit, SSRF himoyasi, tokensiz         │
        │                                                             │
        │  nst-console konteyner (host network) 127.0.0.1:8765        │
        │    NST_WEB_MODE=console, faqat NET_RAW + NET_ADMIN          │
        │    token bilan himoyalangan, internetga ochiq emas          │
        └──────────────────────────────▲──────────────────────────────┘
                                       │ SSH tunnel (deploy foydalanuvchisi)
                                    Egasi
```

**Nega ikki qism?** Paket ushlash (sniffing) xavfli imkoniyat. U ochiq
internetga chiqarilmasligi kerak. Shuning uchun:

- **Public demo** faqat xavfsiz funksiyalarni beradi: TLS skan va GeoIP.
  Board, Traffic, Network va Reports bo'limlari yopiq va `403 public_demo`
  qaytaradi.
- **Maxfiy konsol** to'liq imkoniyatga ega, lekin faqat `127.0.0.1` da
  tinglaydi. Unga SSH tunnel orqali, token bilan kiriladi.

---

## 3. Ikki repo

| Repo | Ichida nima bor | Reliz natijasi |
|---|---|---|
| [network-security-toolkit](https://github.com/khikmat64168-cyber/network-security-toolkit) | Python backend, CLI, Dockerfile, deploy skriptlari | Docker image (GHCR), wheel (GitHub Release), ikkala deploy |
| [Networkscan-front](https://github.com/khikmat64168-cyber/Networkscan-front) | React + Vite + TypeScript web konsol | `networkscan-front-vX.Y.Z.tar.gz` va `.sha256` (GitHub Release) |

Backend qaysi frontend versiyasini olishini `frontend.version` fayli
belgilaydi. Image va wheel yig'ilayotganda `scripts/fetch_frontend.sh --release`
o'sha relizni yuklab oladi, SHA-256 bilan tekshiradi va `src/nst/web/static/`
ichiga joylaydi. Shuning uchun wheel ham, image ham tayyor konsol bilan keladi.

---

## 4. Qadamma-qadam: nima qilindi

### 4.1. Loyihani deployga tayyorlash

- Kod `nst` paketiga (src layout) ko'chirildi. Endi `nst` buyrug'i
  `pip install` dan keyin ishlaydi.
- TLS skaner buzuq edi: `CERT_NONE` bilan `getpeercert()` bo'sh qaytarardi.
  Endi sertifikat DER ko'rinishida olinib, `cryptography` bilan o'qiladi.
- Config va log yo'llari XDG standartiga o'tkazildi, shu sababli konteynerda
  `read-only` fayl tizimi bilan ishlaydi.
- Web konsol uch rejimda ishlaydigan qilindi:
  - `local`: har ishga tushishda yangi tasodifiy token, faqat loopback;
  - `console`: `NST_WEB_TOKEN` dan olinadigan doimiy token, faqat loopback;
  - `public`: token yo'q, capture yo'q, rate-limit va SSRF himoyasi bor,
    konteyner ichida `0.0.0.0` ga ulanishi mumkin.

### 4.2. Frontend'ni alohida repoga chiqarish

Web konsol `Networkscan-front` repo'siga ko'chirildi. Uning o'z CI'si
(typecheck, test, build, litsenziya tekshiruvi) va Release workflow'i bor.
Release workflow faqat build arxivini nashr qiladi, serverga hech narsa
deploy qilmaydi va secret talab qilmaydi.

### 4.3. Docker image

`Dockerfile` ikki bosqichli (build va runtime), `python:3.12-slim` asosida:

- `nst` foydalanuvchisi bilan ishlaydi (uid 10001, root emas);
- `libpcap0.8` o'rnatilgan, paket ushlash shu kutubxona orqali ishlaydi;
- standart rejim `public`, port `8766`;
- `HEALTHCHECK` Python orqali `/api/mode` ni tekshiradi, chunki image'da
  `curl` va `wget` yo'q;
- `NST_TRUSTED_PROXIES` ichki tarmoqlarni ishonchli proxy deb biladi.
  Shuning uchun rate-limit haqiqiy mijoz IP'si bo'yicha ishlaydi, Traefik
  IP'si bo'yicha emas.

### 4.4. Muhim burilish: serverda Coolify borligi aniqlandi

Dastlabki reja serverga Docker'ni o'rnatish, ufw firewall sozlash va 80/443
portlarda Caddy ishga tushirish edi. Hech narsa o'zgartirishdan oldin server
tekshirildi va unda **Coolify** (Traefik bilan) hamda boshqa ishlab turgan
ilovalar borligi ma'lum bo'ldi.

O'sha reja amalga oshirilganda Coolify va boshqa saytlar ishdan chiqardi.
Shuning uchun reja to'xtatildi va yangi reja tuzildi:

- Public demo **Coolify resursi** sifatida qo'shiladi. HTTPS'ni Coolify'ning
  Traefik'i beradi.
- Maxfiy konsol alohida `docker compose` bilan ko'tariladi, faqat loopback'da.
- Docker, firewall va boshqa konteynerlarga **tegilmaydi**.

Eski `vps-setup.sh`, `Caddyfile` va `deploy.sh` fayllari o'chirildi.

### 4.5. Domen va DNS (Hostinger)

1. `scannetwork.io` domeni Hostinger'dan olindi.
2. Yangi domenda yozuv qo'shishda **"domain not found"** xatosi chiqdi.
   Sababi: Hostinger nameserver'lari hali DNS zonani yaratmagan edi
   (so'rovlarga `REFUSED` qaytarardi). **Reset DNS records** zonani yaratdi.
3. Qo'shilgan yozuvlar:
   - `A @` → server IP, TTL 3600;
   - `CNAME www` → `scannetwork.io`.
4. Muammo: Reset Hostinger'ning yashirin **parking IP**'sini ham qaytargan
   edi. U panelda ko'rinmasdi, lekin DNS javobida qatnashardi. Bir necha
   soatdan keyin o'z-o'zidan yo'qoldi.

> **TTL** port emas. U DNS yozuvi necha soniya keshda saqlanishini
> bildiradi (3600 = 1 soat). Portni DNS'da sozlash kerak emas, HTTPS
> avtomatik 443 portdan ishlaydi.

### 4.6. Maxfiy konsol uchun serverni tayyorlash

`deploy/console-setup.sh` server egasi tomonidan root sifatida **bir marta**
ishga tushirildi. U:

- `deploy` foydalanuvchisini yaratadi, `docker` guruhiga qo'shadi va
  GitHub Actions kalitining ochiq qismini qo'yadi;
- `/opt/nst-console/.env` faylini tasodifiy konsol tokeni bilan yaratadi
  (huquqlari `600`, egasi `deploy`).

Skript Docker, firewall va mavjud konteynerlarga tegmaydi.

Konsol konteyneri (`deploy/console/docker-compose.yml`) quyidagicha
sozlangan:

- `network_mode: host`, chunki sensorlar serverning haqiqiy tarmoq
  interfeysini ko'rishi kerak;
- faqat `127.0.0.1:8765` da tinglaydi;
- `read_only`, `cap_drop: ALL`, faqat `NET_RAW` va `NET_ADMIN` qo'shilgan,
  `no-new-privileges`.

### 4.7. Coolify'da public demo

Coolify'da `scannetwork` loyihasi va **Docker Image** turidagi resurs
yaratildi:

| Sozlama | Qiymat |
|---|---|
| Image | `ghcr.io/khikmat64168-cyber/network-security-toolkit:latest` |
| Ports exposes | `8766` |
| Domains | `https://scannetwork.io`, `https://www.scannetwork.io` |
| Environment | `NST_ALLOWED_HOSTS=scannetwork.io www.scannetwork.io` |
| Custom Docker options | `--cap-drop ALL` |
| Coolify health check | O'chiq (image'ning o'z `HEALTHCHECK`'i ishlaydi) |

Coolify Let's Encrypt sertifikatini o'zi oldi va HTTP so'rovlarini HTTPS'ga
yo'naltiradi.

GHCR'dagi image ommaviy, chunki repo ommaviy. Coolify ham, server ham uni
login qilmasdan yuklab oladi.

### 4.8. GitHub sozlamalari (backend repo)

**Secrets** (Settings → Secrets and variables → Actions):

| Nomi | Nima |
|---|---|
| `COOLIFY_DEPLOY_WEBHOOK` | Coolify resursining deploy webhook URL'i |
| `COOLIFY_API_TOKEN` | Coolify API tokeni, **`deploy`** ruxsati bilan |
| `VPS_HOST` | Server manzili |
| `VPS_SSH_KEY` | `deploy` foydalanuvchisining maxfiy SSH kaliti |
| `VPS_KNOWN_HOSTS` | Serverning SSH host kaliti (MITM himoyasi uchun) |

**Variables:** `PUBLIC_URL=https://scannetwork.io`.
**Environment:** `production`.

---

## 5. CI/CD qanday ishlaydi

### Har bir push'da (`ci.yml`)

- Python 3.12 va 3.13 da `flake8`, `mypy` va `pytest` (563 ta test);
- Docker image yig'iladi va qisqa smoke test o'tkaziladi;
- deploy skriptlari `shellcheck` bilan tekshiriladi.

### Tag push qilinganda (`release.yml`)

```
git push origin vX.Y.Z
        │
        ▼
     verify ── tag nst.__version__ ga mosmi?
        │
   ┌────┴─────┐
   ▼          ▼
 image      wheel ── frontend relizini yuklab, wheel'ni GitHub Release'ga qo'yadi
   │
   │  ghcr.io/...:vX.Y.Z va :latest
   │
   ├──► deploy-public:  Coolify webhook'iga POST so'rov
   │                    → https://scannetwork.io/api/mode yangi versiyani
   │                      qaytarguncha kutadi
   │
   └──► deploy-console: SSH (deploy@server) orqali compose fayli va skript
                        ko'chiriladi → deploy-console.sh vX.Y.Z
                        → health tekshiruv, muvaffaqiyatsiz bo'lsa
                          avtomatik oldingi versiyaga qaytadi
```

Frontend repo'da tag push qilinsa, faqat build arxivi va uning SHA-256
fayli GitHub Release'ga chiqadi.

---

## 6. Yo'lda chiqqan muammolar va yechimlar

| Belgisi | Sababi | Yechim |
|---|---|---|
| `image` va `wheel` "Bundle the pinned web console" qadamida yiqildi | `fetch_frontend.sh` ichida `local tmp`, EXIT trap esa funksiya tugagandan keyin ishlaydi; `set -u` "unbound variable" deb to'xtatadi | `tmp` global qilindi (v1.0.0 qayta teglandi, chunki hali hech narsa nashr qilinmagan edi) |
| Coolify deploy: `invalid security-opt: "no"` | Coolify `--security-opt no-new-privileges` ni noto'g'ri tahlil qiladi | Faqat `--cap-drop ALL` qoldirildi (image baribir root emas) |
| Coolify health check'i mos kelmaydi | U `curl`/`wget` bilan tekshiradi, image'da ular yo'q | Coolify check o'chiq, image'ning Python `HEALTHCHECK`'i ishlaydi |
| Webhook `403` | API tokenda faqat `read` ruxsati bor edi | Yangi token, **`deploy`** ruxsati bilan |
| Webhook `405` | Coolify 4.4+ `/api/v1/deploy` uchun faqat **POST** qabul qiladi | Workflow'da `curl -X POST` (v1.0.1) |
| Eski run'ni qayta ishga tushirish yordam bermadi | Re-run workflow'ni eski tag'dagi commit'dan oladi | Yangi reliz (`v1.0.1`) |
| Maxfiy konsolda qora ekran | Token `NST_WEB_TOKEN=…` bilan joylandi, brauzer bunday WebSocket subprotocol'ni rad etadi va ilova qulaydi | Frontend tokenni tozalaydi, noto'g'ri qiymatda xabar chiqaradi, WebSocket xatosi sahifani qulatmaydi (front v1.0.1, backend v1.0.2) |
| O'rnatish ko'rsatmasi ishlamasdi | Ko'rsatma PyPI'ga yo'naltirardi, paket esa u yerda yo'q | Ko'rsatma endi GitHub Release wheel'idan o'rnatadi (front v1.0.2, backend v1.0.3) |
| Versiya bir necha joyda qo'lda yozilgan edi | Banner va hisobotda `1.0.0` qolib ketgan | Ikkalasi ham endi `nst.__version__` dan oladi |

---

## 7. Yangi versiya chiqarish

**Faqat backend o'zgargan bo'lsa:**

1. `src/nst/__init__.py` faylida `__version__` ni oshiring.
2. `CHANGELOG.md` ga yozuv qo'shing.
3. `README.md` dagi wheel o'rnatish qatoridagi versiyani yangilang.
4. Commit qiling, keyin push va tag:

```bash
git push origin main && git tag vX.Y.Z && git push origin vX.Y.Z
```

**Frontend ham o'zgargan bo'lsa** (tartib muhim):

1. Networkscan-front repo'sida `package.json` versiyasini oshiring, commit
   qiling, `git tag vA.B.C && git push origin vA.B.C`.
2. Frontend relizi chiqishini kuting (taxminan 1 daqiqa).
3. Backend repo'sida `frontend.version` faylini `vA.B.C` ga o'zgartiring va
   yuqoridagi backend qadamlarini bajaring.

Qolgan hammasini GitHub Actions bajaradi. Natijani **Actions** tab'ida
kuzatish mumkin.

**Agar biror deploy job'i yiqilsa:** sababini tuzating va **yangi**
versiya chiqaring. Re-run faqat secret yoki server tomonidagi muammo
tuzatilgan bo'lsa yordam beradi, chunki workflow kodi eski tag'dan olinadi.

---

## 8. Ishlatish

### Public demo

https://scannetwork.io ni oching. TLS bo'limida domen yozib sertifikatni,
GeoIP bo'limida IP joylashuvini tekshirasiz. Token kerak emas.

### O'z kompyuterida (to'liq versiya)

```bash
python3 -m venv nst-env
nst-env/bin/pip install "network-security-toolkit[web] @ https://github.com/khikmat64168-cyber/network-security-toolkit/releases/download/v1.0.3/network_security_toolkit-1.0.3-py3-none-any.whl"
sudo nst-env/bin/nst web
```

Brauzer bir martalik token bilan o'zi ochiladi. Hech kimdan token so'rash
shart emas.

### Maxfiy konsol (faqat egasi)

1. Tunnelni oching (bu oyna ochiq turishi kerak):

```bash
ssh -i ~/.ssh/nst_deploy -N -L 8765:127.0.0.1:8765 deploy@scannetwork.io
```

2. Tokenni ko'ring:

```bash
ssh -i ~/.ssh/nst_deploy deploy@scannetwork.io "grep NST_WEB_TOKEN /opt/nst-console/.env"
```

3. Brauzerda `http://127.0.0.1:8765/` ni oching va tokenni joylang.

4. Tokenni almashtirish kerak bo'lsa:

```bash
ssh -i ~/.ssh/nst_deploy deploy@scannetwork.io 'cd /opt/nst-console && t=$(openssl rand -base64 48 | tr -d "\n=+/" | cut -c1-48) && sed -i "s/^NST_WEB_TOKEN=.*/NST_WEB_TOKEN=$t/" .env && docker compose up -d'
```

---

## 9. Xavfsizlik bo'yicha qisqacha

- Public demo token talab qilmaydi, lekin paket ushlay olmaydi, fayl
  saqlamaydi va faqat ommaviy IP'larni skanerlaydi (SSRF himoyasi).
  So'rovlar soni cheklangan: daqiqasiga 6 ta TLS host va 20 ta GeoIP so'rovi.
- Begona `Host` sarlavhasi bilan kelgan so'rov `421` bilan rad etiladi.
- Maxfiy konsol internetga umuman ochilmaydi va token bilan himoyalangan.
- `deploy` foydalanuvchisida root huquqi yo'q. Uning kaliti faqat GitHub
  secret'ida va egasining kompyuterida saqlanadi.
- Secret'lar, tokenlar va maxfiy kalitlar repo'ga hech qachon yozilmaydi.
  `deploy/.env` `.gitignore` da turibdi.
