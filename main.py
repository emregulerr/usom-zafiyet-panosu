import requests
import re
import time
import csv
import datetime
import os
import argparse
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px

# --- CONFIGURATION ---
# 17 Mayıs 2026 duyurusu: USOM içerikleri Siber Güvenlik Başkanlığı'nın yeni
# domain'ine taşındı. API artık siberguvenlik.gov.tr apex domain'i üzerinden
# JSON döndürüyor (şema usom.gov.tr ile birebir aynı: totalCount/pageCount/models).
# Önemli not: `www.` subdomain'i Angular SPA'ya gidiyor ve tüm bilinmeyen path'ler
# için HTML döndürdüğü için kullanılamaz; apex domain (www.'siz) zorunlu.
# Geçiş döneminde eski usom.gov.tr endpoint'i hâlâ çalıştığı için USOM_API_URL
# ortam değişkeni ile override edilebilir (GitHub Actions tarafında repo secret).
DEFAULT_API_URL = "https://siberguvenlik.gov.tr/api/incident/index"
# `or` kullanıyoruz: GitHub Actions tanımsız secret'ı boş string olarak geçirir,
# `os.environ.get(..., DEFAULT)` ise boş string'i "tanımlı" sayıp default'a düşmez.
API_URL = os.environ.get("USOM_API_URL") or DEFAULT_API_URL

# File/Directory Paths
OUTPUT_DIR = "output"
IMAGES_DIR = os.path.join(OUTPUT_DIR, "images")
CHARTS_DIR = os.path.join(OUTPUT_DIR, "charts")  # Plotly HTML çıktıları (gh-pages için)
OUTPUT_CSV_FILENAME = "vulnerabilities_data.csv"

# API Rate Limiting
# USOM resmi bir rate-limit yayınlamıyor ve X-RateLimit-* header'ı döndürmüyor.
# Empirik olarak ~20 istek/dk üzerinde HTTP 429 alınıyor; bu yüzden istekler
# arası 3 saniye bekliyor, 429 alındığında exponential backoff uyguluyoruz.
REQUESTS_PER_MINUTE = 20
DELAY_SECOND = 60 / REQUESTS_PER_MINUTE  # 3 sn
MAX_RETRIES = 5

def valid_date(s):
    """Tarih formatını (YYYY-MM-DD) kontrol eden yardımcı fonksiyon."""
    try:
        # Saat, dakika ve saniye bilgisini sıfırlayarak sadece tarihi alır
        dt = datetime.datetime.strptime(s, "%Y-%m-%d")
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    except ValueError:
        msg = f"Geçerli bir tarih formatı değil: '{s}'. Lütfen YYYY-MM-DD formatını kullanın."
        raise argparse.ArgumentTypeError(msg)

def fetch_vulnerabilities(api_url, page, date_gte=None):
    """
    API'den belirli bir sayfadan ve tarihten itibaren zafiyet verilerini çeker.
    HTTP 429 durumunda Retry-After header'ına (yoksa exponential backoff'a) uyar.

    :param api_url: API URL'si
    :param page: Çekilecek sayfa numarası
    :param date_gte: Bu tarihten sonra çekilecek zafiyetler
    :return: JSON formatında zafiyet verileri veya None
    """
    params = {"page": page, "per-page": 50}
    if date_gte:
        params["date_gte"] = date_gte

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(api_url, params=params, timeout=30)
        except requests.RequestException as e:
            backoff = min(60, 2 ** attempt)
            print(f"İstek hatası (deneme {attempt}/{MAX_RETRIES}): {e}. {backoff}s bekleniyor.")
            time.sleep(backoff)
            continue

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            wait = int(retry_after) if retry_after and retry_after.isdigit() else min(120, 2 ** attempt * 5)
            print(f"429 alındı (deneme {attempt}/{MAX_RETRIES}). {wait}s bekleniyor.")
            time.sleep(wait)
            continue

        try:
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"API'den veri alınırken hata oluştu: {e}")
            return None

        time.sleep(DELAY_SECOND)
        return response.json()

    print(f"Sayfa {page} için maksimum yeniden deneme aşıldı; bu sayfa atlanıyor.")
    return None

def fetch_all_vulnerabilities(api_url, date_gte, max_pages=500):
    """
    API'den belirli bir tarihten itibaren zafiyet verilerini çeker.

    USOM API son sayfayı geçtikten sonra boş liste döndürmek yerine son sayfanın
    aynı sonuçlarını sonsuza dek tekrarladığı için sayfa sayısını ilk yanıttan
    gelen `pageCount` alanına göre sınırlıyoruz. `max_pages` regression'lara karşı
    son savunma hattı.
    """
    vulnerabilities = []
    cutoff = date_gte.strftime("%Y-%m-%d")

    first = fetch_vulnerabilities(api_url, 1, cutoff)
    if first is None:
        print("İlk sayfa alınamadı; veri yok.")
        return vulnerabilities

    page_count = int(first.get("pageCount") or 0)
    total_count = int(first.get("totalCount") or 0)
    print(
        f"{cutoff} tarihinden itibaren {total_count} kayıt / {page_count} sayfa "
        f"alınıyor (max {max_pages})..."
    )

    vulnerabilities.extend(first.get("models") or [])
    last_page = min(page_count, max_pages)
    if page_count > max_pages:
        print(f"Uyarı: pageCount={page_count} > max_pages={max_pages}; veri kesilecek.")

    for current_page in range(2, last_page + 1):
        page_data = fetch_vulnerabilities(api_url, current_page, cutoff)
        if page_data is None:
            print(f"Sayfa {current_page} alınamadı, çekim durduruluyor.")
            break
        models = page_data.get("models") or []
        if not models:
            break
        vulnerabilities.extend(models)

    return vulnerabilities

def normalize(data):
    """
    Veriyi normalize eder, özel karakterleri ve boşlukları kaldırır.

    :param data: Normalleştirilecek veri
    :return: Normalleştirilmiş veri
    """
    data = data.lower().replace(",", "|").replace("\n", " ").replace(" ", "-").replace("_", "-").replace(".", "-")
    data = re.sub(r"[{}[\]()=:;!?+*/\\'\"<>`~@#$%^&|çğıöşüâîû]", "", data)
    data = re.sub(r"-+", "-", data)
    return data

def save_vulnerabilities_to_csv(vulnerabilities, filename):
    """
    Zafiyet verilerini CSV dosyasına kaydeder.

    :param vulnerabilities: Kaydedilecek zafiyet verileri
    :param filename: CSV dosyasının adı ve yolu
    :return: Eşsiz zafiyet verilerinin listesi
    """
    unique_vulnerabilities = []
    seen_titles = set()
    for vuln in vulnerabilities:
        if vuln.get("title") and vuln.get("tags") and vuln.get("date"):
            normalized_title = normalize(vuln["title"])
            if normalized_title not in seen_titles:
                unique_vulnerabilities.append([normalized_title, normalize(vuln["tags"]), vuln["date"]])
                seen_titles.add(normalized_title)

    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, escapechar='\\')
        writer.writerow(["Başlık", "Etiketler", "Tarih"])
        writer.writerows(unique_vulnerabilities)
    print(f"Zafiyetler {filename} dosyasına kaydedildi")

    return unique_vulnerabilities

def generate_visualizations(vulnerabilities, title_suffix="", save_dir=None):
    """
    Zafiyet verilerini görselleştirir ve dosyalara kaydeder.

    :param vulnerabilities: Görselleştirilecek zafiyet verileri
    :param title_suffix: Grafik başlıkları için eklenecek ek bilgi
    :param save_dir: Görsellerin kaydedileceği klasör
    """
    tags = {}
    for vuln in vulnerabilities:
        if vuln[1]:
            for tag in vuln[1].split("|"):
                tag = normalize(tag)
                tags[tag] = tags.get(tag, 0) + 1

    date_counts = {}
    for vuln in vulnerabilities:
        if vuln[2]:
            date = vuln[2].split("T")[0]
            year_month = date[:7]
            date_counts[year_month] = date_counts.get(year_month, 0) + 1

    if date_counts:
        sorted_date_counts = sorted(date_counts.items())
        months = [month for month, count in sorted_date_counts]
        counts = [count for month, count in sorted_date_counts]

        plt.figure(figsize=(12, 7))
        plt.plot(months, counts, marker='o')
        plt.xlabel('Aylar')
        plt.ylabel('Zafiyet Sayısı')
        plt.title(f'Aya Göre Zafiyet Sayısı\n{title_suffix}')
        plt.xticks(rotation=90)
        plt.grid(True)

        save_path = os.path.join(save_dir, "time_series_chart.png")
        plt.savefig(save_path, bbox_inches='tight')
        print(f"Grafik kaydedildi: {save_path}")
        plt.close()
    else:
        print("Belirtilen aralıkta veri bulunamadı, zaman serisi grafiği oluşturulamadı.")

    if tags:
        top_tags = 10
        sorted_tags_by_count = sorted(tags.items(), key=lambda x: x[1], reverse=True)
        top_tags_by_count = sorted_tags_by_count[:top_tags]

        top_tags_df = pd.DataFrame(top_tags_by_count, columns=['Etiket', 'Sayı'])
        plt.figure(figsize=(12, 8))
        sns.barplot(data=top_tags_df, x='Sayı', y='Etiket', palette='viridis')
        plt.title(f'En Çok Kullanılan 10 Etiket ve Sayıları\n{title_suffix}')

        save_path = os.path.join(save_dir, "top_tags_chart.png")
        plt.savefig(save_path, bbox_inches='tight')
        print(f"Grafik kaydedildi: {save_path}")
        plt.close()

        sorted_tags_by_month = {}
        for vuln in vulnerabilities:
            if vuln[1] and vuln[2]:
                for tag in vuln[1].split("|"):
                    tag = normalize(tag)
                    year_month = vuln[2].split("T")[0][:7]
                    if year_month not in sorted_tags_by_month:
                        sorted_tags_by_month[year_month] = {}
                    sorted_tags_by_month[year_month][tag] = sorted_tags_by_month[year_month].get(tag, 0) + 1

        top_10_tags = [tag for tag, count in sorted_tags_by_count[:top_tags]]

        heatmap_data = pd.DataFrame(index=sorted(sorted_tags_by_month.keys()), columns=top_10_tags)
        for month, tags_in_month in sorted_tags_by_month.items():
            for tag in top_10_tags:
                heatmap_data.at[month, tag] = tags_in_month.get(tag, 0)
        heatmap_data = heatmap_data.fillna(0)

        plt.figure(figsize=(14, 10))
        sns.heatmap(heatmap_data.astype(int), cmap="YlGnBu", annot=True, fmt="d")
        plt.title(f'Türkiye Zafiyet Sıcaklık Haritası\n{title_suffix}')
        plt.xlabel('Etiketler')
        plt.ylabel('Aylar')

        save_path = os.path.join(save_dir, "heatmap.png")
        plt.savefig(save_path, bbox_inches='tight')
        print(f"Grafik kaydedildi: {save_path}")
        plt.close()
    else:
        print("Belirtilen aralıkta veri bulunamadı, etiket ve sıcaklık haritası grafikleri oluşturulamadı.")


_CHART_LAYOUT_DEFAULTS = dict(
    margin=dict(l=10, r=10, t=40, b=10),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, sans-serif"),
    title=None,  # Başlık dış kart başlığında zaten var; çift göstermiyoruz.
)


def generate_interactive_html(vulnerabilities, title_suffix, save_dir, start_date, end_date):
    """
    Tek sayfa, modern, koyu-açık tema duyarlı, KPI kartlı interaktif pano üretir.
    Plotly.js tek seferlik CDN load + her grafik aynı sayfada <div> olarak gömülür
    (iframe yok — daha hızlı, tutarlı stil, çift scroll yok).
    """
    os.makedirs(save_dir, exist_ok=True)

    # --- KPI hesaplama ---
    total = len(vulnerabilities)
    days = max((end_date - start_date).days, 1)
    daily_avg = round(total / days, 1)

    tag_counts = {}
    tags_by_month = {}
    date_counts = {}
    latest_date = ""

    for v in vulnerabilities:
        if v[2]:
            day = v[2].split("T")[0]
            ym = day[:7]
            date_counts[ym] = date_counts.get(ym, 0) + 1
            if day > latest_date:
                latest_date = day
        if v[1]:
            ym = v[2].split("T")[0][:7] if v[2] else None
            for tag in v[1].split("|"):
                tag = normalize(tag)
                if not tag:
                    continue
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
                if ym:
                    tags_by_month.setdefault(ym, {}).setdefault(tag, 0)
                    tags_by_month[ym][tag] += 1

    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
    top_tag_name = sorted_tags[0][0] if sorted_tags else "—"
    unique_tags = len(tag_counts)

    # --- Plotly figürleri (tek sayfaya gömmek için full_html=False, plotly.js yok) ---
    def to_div(fig):
        return fig.to_html(include_plotlyjs=False, full_html=False, div_id=None)

    ts_div = "<p class='empty'>Veri yok.</p>"
    if date_counts:
        df_ts = pd.DataFrame(sorted(date_counts.items()), columns=["Ay", "Zafiyet Sayısı"])
        fig = px.line(df_ts, x="Ay", y="Zafiyet Sayısı", markers=True)
        fig.update_traces(line=dict(width=3, color="#2563eb"), marker=dict(size=8))
        fig.update_layout(height=380, hovermode="x unified", **_CHART_LAYOUT_DEFAULTS)
        ts_div = to_div(fig)

    tags_div = "<p class='empty'>Veri yok.</p>"
    if sorted_tags:
        df_tags = pd.DataFrame(sorted_tags[:10], columns=["Etiket", "Sayı"])
        fig = px.bar(
            df_tags, x="Sayı", y="Etiket", orientation="h",
            color="Sayı", color_continuous_scale="Blues",
        )
        fig.update_layout(
            height=420, coloraxis_showscale=False,
            yaxis={"categoryorder": "total ascending"},
            **_CHART_LAYOUT_DEFAULTS,
        )
        tags_div = to_div(fig)

    heat_div = "<p class='empty'>Veri yok.</p>"
    if tags_by_month and sorted_tags:
        top_10 = [t for t, _ in sorted_tags[:10]]
        pivot = pd.DataFrame(index=sorted(tags_by_month.keys()), columns=top_10).fillna(0)
        for month, tags_in_month in tags_by_month.items():
            for tag in top_10:
                pivot.at[month, tag] = tags_in_month.get(tag, 0)
        fig = px.imshow(
            pivot.astype(int), text_auto=True, aspect="auto",
            color_continuous_scale="Blues",
            labels=dict(x="Etiket", y="Ay", color="Sayı"),
        )
        fig.update_layout(height=460, **_CHART_LAYOUT_DEFAULTS)
        heat_div = to_div(fig)

    # --- Sayfa şablonu (CSS curly brace'lerinden kaçınmak için .replace) ---
    last_updated_dt = datetime.datetime.now()
    template = """<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>USOM Zafiyet Panosu — İnteraktif</title>
  <meta name="description" content="Türkiye USOM zafiyet bildirimlerinin canlı interaktif panosu. Her gün otomatik güncellenir.">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E%F0%9F%9B%A1%EF%B8%8F%3C/text%3E%3C/svg%3E">
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js" charset="utf-8"></script>
  <style>
    :root {
      --bg: #f8fafc;
      --surface: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --accent: #2563eb;
      --shadow: 0 1px 3px rgba(0,0,0,.05), 0 1px 2px rgba(0,0,0,.04);
      --shadow-lg: 0 10px 25px -5px rgba(0,0,0,.1), 0 8px 10px -6px rgba(0,0,0,.05);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0b1220;
        --surface: #131c2e;
        --text: #f1f5f9;
        --text-muted: #94a3b8;
        --border: #1f2a3f;
        --shadow: 0 1px 3px rgba(0,0,0,.4);
        --shadow-lg: 0 10px 25px -5px rgba(0,0,0,.5);
      }
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    .container { max-width: 1280px; margin: 0 auto; padding: 0 1.5rem; }
    header {
      background: linear-gradient(135deg, #1e3a8a 0%, #0f172a 60%, #020617 100%);
      color: #f1f5f9; padding: 2.5rem 0 4rem;
      position: relative; overflow: hidden;
    }
    header::before {
      content: ''; position: absolute; inset: 0;
      background: radial-gradient(circle at 80% 20%, rgba(37,99,235,.25), transparent 50%);
      pointer-events: none;
    }
    header h1 {
      margin: 0 0 .35rem; font-size: 2.25rem; font-weight: 700; letter-spacing: -.02em;
      position: relative;
    }
    header .subtitle {
      margin: 0; color: #cbd5e1; font-size: 1rem; position: relative;
    }
    .badges {
      margin-top: 1.25rem; display: flex; gap: .5rem; flex-wrap: wrap;
      position: relative;
    }
    .badge {
      display: inline-flex; align-items: center; gap: .35rem;
      padding: .4rem .85rem; background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 999px; font-size: .82rem; color: #f1f5f9;
      text-decoration: none; transition: background .15s, border-color .15s;
      backdrop-filter: blur(8px);
    }
    .badge:hover { background: rgba(255,255,255,.16); border-color: rgba(255,255,255,.25); }
    main { padding-bottom: 3rem; }
    .kpis {
      display: grid; gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      margin-top: -2.5rem; margin-bottom: 2rem; position: relative; z-index: 2;
    }
    .kpi {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; padding: 1.25rem 1.4rem;
      box-shadow: var(--shadow-lg);
      transition: transform .15s ease;
    }
    .kpi:hover { transform: translateY(-2px); }
    .kpi-label {
      font-size: .72rem; color: var(--text-muted);
      text-transform: uppercase; letter-spacing: .08em; font-weight: 600;
    }
    .kpi-value {
      font-size: 2rem; font-weight: 700; margin-top: .35rem;
      color: var(--text); line-height: 1.1;
      font-feature-settings: 'tnum';
    }
    .kpi-value.accent { color: var(--accent); }
    .kpi-value.small { font-size: 1.15rem; line-height: 1.3; word-break: break-word; }
    .chart-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 14px; padding: 1.5rem; margin-bottom: 1.5rem;
      box-shadow: var(--shadow);
    }
    .chart-card h2 {
      margin: 0 0 .25rem; font-size: 1.05rem; font-weight: 600;
      color: var(--text); display: flex; align-items: center; gap: .5rem;
    }
    .chart-card .chart-sub {
      margin: 0 0 1rem; color: var(--text-muted); font-size: .85rem;
    }
    .empty { color: var(--text-muted); text-align: center; padding: 2rem; }
    footer {
      border-top: 1px solid var(--border); padding: 1.5rem 0;
      color: var(--text-muted); font-size: .85rem; margin-top: 2rem;
    }
    footer a { color: var(--accent); text-decoration: none; }
    footer a:hover { text-decoration: underline; }
    .meta-row {
      display: flex; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      align-items: center;
    }
    /* Plotly modebar dark uyumu */
    @media (prefers-color-scheme: dark) {
      .js-plotly-plot .plotly .modebar { filter: invert(.85); }
    }
    @media (max-width: 640px) {
      header { padding: 2rem 0 3.5rem; }
      header h1 { font-size: 1.75rem; }
      .kpi-value { font-size: 1.6rem; }
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>🛡️ USOM Zafiyet Panosu</h1>
      <p class="subtitle">Türkiye'nin güvenlik bildirimleri — her gün otomatik güncellenir</p>
      <div class="badges">
        <a class="badge" href="https://github.com/emregulerr/usom-zafiyet-panosu">📦 GitHub</a>
        <a class="badge" href="https://usom-zafiyet-panosu.streamlit.app/">🚀 Streamlit (filtreli)</a>
        <a class="badge" href="https://siberguvenlik.gov.tr">🔗 Veri kaynağı</a>
        <a class="badge" href="./vulnerabilities_data.csv">⬇️ CSV indir</a>
      </div>
    </div>
  </header>
  <main class="container">
    <section class="kpis" aria-label="Anahtar metrikler">
      <div class="kpi">
        <div class="kpi-label">Toplam Zafiyet</div>
        <div class="kpi-value accent">__TOTAL__</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Günlük Ortalama</div>
        <div class="kpi-value">__DAILY__</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Eşsiz Etiket</div>
        <div class="kpi-value">__TAGS__</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">En Popüler Etiket</div>
        <div class="kpi-value small">__TOP_TAG__</div>
      </div>
    </section>

    <article class="chart-card">
      <h2>📈 Aylara Göre Zafiyet Sayısı</h2>
      <p class="chart-sub">Yayınlanan bildirimlerin zaman içindeki dağılımı.</p>
      __TS_DIV__
    </article>

    <article class="chart-card">
      <h2>🏷️ En Çok Kullanılan 10 Etiket</h2>
      <p class="chart-sub">Hangi ürün/teknoloji ailelerinde en yoğun zafiyet duyurusu var?</p>
      __TAGS_DIV__
    </article>

    <article class="chart-card">
      <h2>🔥 Aylık Etiket Yoğunluğu</h2>
      <p class="chart-sub">Hangi etiketin hangi ayda öne çıktığını gösteren ısı haritası.</p>
      __HEAT_DIV__
    </article>
  </main>
  <footer>
    <div class="container meta-row">
      <div>
        Aralık: <strong>__START__ – __END__</strong> · Son güncelleme: <strong>__UPDATED__</strong>
      </div>
      <div>
        Geliştiren <a href="https://github.com/emregulerr">Emre Güler</a> · MIT
      </div>
    </div>
  </footer>
</body>
</html>
"""
    html = (
        template
        .replace("__TOTAL__", f"{total:,}".replace(",", "."))
        .replace("__DAILY__", f"{daily_avg:.1f}".rstrip("0").rstrip(".") or "0")
        .replace("__TAGS__", f"{unique_tags:,}".replace(",", "."))
        .replace("__TOP_TAG__", top_tag_name)
        .replace("__TS_DIV__", ts_div)
        .replace("__TAGS_DIV__", tags_div)
        .replace("__HEAT_DIV__", heat_div)
        .replace("__START__", start_date.strftime("%d.%m.%Y"))
        .replace("__END__", end_date.strftime("%d.%m.%Y"))
        .replace("__UPDATED__", last_updated_dt.strftime("%d.%m.%Y %H:%M"))
    )

    index_path = os.path.join(save_dir, "index.html")
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(html)

    # CSV'yi de Pages'e kopyala — header'daki "CSV indir" linki için.
    csv_src = os.path.join(OUTPUT_DIR, OUTPUT_CSV_FILENAME)
    if os.path.exists(csv_src):
        import shutil
        shutil.copy2(csv_src, os.path.join(save_dir, OUTPUT_CSV_FILENAME))

    print(f"İnteraktif HTML pano kaydedildi: {index_path}")


def main():
    """Ana çalışma fonksiyonu, verileri çekip kaydeder ve görselleştirir."""
    parser = argparse.ArgumentParser(
        description="USOM'dan zafiyet verilerini çeker, analiz eder ve görselleştirir.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--days", type=int, help="Analizin bitiş tarihinden kaç gün geriye gidileceğini belirtir.")
    parser.add_argument("--start-date", type=valid_date, help="Analizin başlangıç tarihi (YYYY-MM-DD).")
    parser.add_argument("--end-date", type=valid_date, help="Analizin bitiş tarihi (YYYY-MM-DD). Varsayılan: bugün.")
    args = parser.parse_args()

    if args.days and args.start_date:
        parser.error("Hata: --days ve --start-date argümanları birlikte kullanılamaz.")

    # Tarih aralığını belirleme mantığı
    now = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    end_date = args.end_date or now

    if args.start_date:
        start_date = args.start_date
    elif args.days:
        start_date = end_date - datetime.timedelta(days=args.days)
    else:
        # Varsayılan: Son 3 ay (90 gün)
        start_date = end_date - datetime.timedelta(days=90)

    if start_date > end_date:
        parser.error(f"Hata: Başlangıç tarihi ({start_date.strftime('%Y-%m-%d')}) bitiş tarihinden ({end_date.strftime('%Y-%m-%d')}) sonra olamaz.")

    os.makedirs(IMAGES_DIR, exist_ok=True)

    all_vulnerabilities = fetch_all_vulnerabilities(API_URL, start_date)

    filtered_vulnerabilities = [
        v for v in all_vulnerabilities
        if start_date.strftime("%Y-%m-%d") <= v.get("date", "")[:10] <= end_date.strftime("%Y-%m-%d")
    ]

    csv_path = os.path.join(OUTPUT_DIR, OUTPUT_CSV_FILENAME)
    unique_vulnerabilities = save_vulnerabilities_to_csv(filtered_vulnerabilities, csv_path)

    title_suffix = f"({start_date.strftime('%d.%m.%Y')} - {end_date.strftime('%d.%m.%Y')})"
    generate_visualizations(unique_vulnerabilities, title_suffix, IMAGES_DIR)
    generate_interactive_html(
        unique_vulnerabilities, title_suffix, CHARTS_DIR, start_date, end_date
    )

    print("\nİşlem tamamlandı.")

if __name__ == "__main__":
    main()