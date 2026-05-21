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


def generate_interactive_html(vulnerabilities, title_suffix, save_dir, start_date, end_date):
    """
    Plotly ile interaktif HTML grafikler üretir (GitHub Pages için).

    Plotly.js CDN'den yüklendiği için her HTML ~50 KB; tüm pano <200 KB.
    Çıktılar: time_series_chart.html, top_tags_chart.html, heatmap.html, index.html
    """
    os.makedirs(save_dir, exist_ok=True)
    plotly_kwargs = {"include_plotlyjs": "cdn", "full_html": True}

    # Zaman serisi
    if vulnerabilities:
        date_counts = {}
        for v in vulnerabilities:
            if v[2]:
                ym = v[2].split("T")[0][:7]
                date_counts[ym] = date_counts.get(ym, 0) + 1
        if date_counts:
            df_ts = pd.DataFrame(
                sorted(date_counts.items()), columns=["Ay", "Zafiyet Sayısı"]
            )
            fig = px.line(
                df_ts, x="Ay", y="Zafiyet Sayısı", markers=True,
                title=f"Aya Göre Zafiyet Sayısı<br><sub>{title_suffix}</sub>",
            )
            fig.update_layout(hovermode="x unified", height=460)
            fig.write_html(os.path.join(save_dir, "time_series_chart.html"), **plotly_kwargs)

    # Top etiketler + ısı haritası
    tag_counts = {}
    tags_by_month = {}
    for v in vulnerabilities:
        if not v[1]:
            continue
        ym = v[2].split("T")[0][:7] if v[2] else None
        for tag in v[1].split("|"):
            tag = normalize(tag)
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            if ym:
                tags_by_month.setdefault(ym, {}).setdefault(tag, 0)
                tags_by_month[ym][tag] += 1

    top_tags = []
    if tag_counts:
        sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        df_tags = pd.DataFrame(sorted_tags, columns=["Etiket", "Sayı"])
        fig = px.bar(
            df_tags, x="Sayı", y="Etiket", orientation="h",
            color="Sayı", color_continuous_scale="Viridis",
            title=f"En Çok Kullanılan 10 Etiket<br><sub>{title_suffix}</sub>",
        )
        fig.update_layout(
            yaxis={"categoryorder": "total ascending"}, height=460, coloraxis_showscale=False,
        )
        fig.write_html(os.path.join(save_dir, "top_tags_chart.html"), **plotly_kwargs)
        top_tags = [t for t, _ in sorted_tags]

    if tags_by_month and top_tags:
        pivot = pd.DataFrame(index=sorted(tags_by_month.keys()), columns=top_tags).fillna(0)
        for month, tags_in_month in tags_by_month.items():
            for tag in top_tags:
                pivot.at[month, tag] = tags_in_month.get(tag, 0)
        fig = px.imshow(
            pivot.astype(int), text_auto=True, aspect="auto",
            color_continuous_scale="YlGnBu",
            labels=dict(x="Etiket", y="Ay", color="Sayı"),
            title=f"Aylık Zafiyet Yoğunluğu (Isı Haritası)<br><sub>{title_suffix}</sub>",
        )
        fig.update_layout(height=560)
        fig.write_html(os.path.join(save_dir, "heatmap.html"), **plotly_kwargs)

    # Kapsayıcı index.html — 3 grafiği iframe'le gömer ve meta bilgi gösterir.
    last_updated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M UTC")
    index_html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>USOM Zafiyet Panosu — İnteraktif</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            max-width: 1200px; margin: 1.5em auto; padding: 0 1em; color: #1f2937; }}
    h1 {{ color: #0f172a; margin-bottom: .25em; }}
    .meta {{ color: #6b7280; font-size: .9em; margin-bottom: 1.5em; }}
    .meta a {{ color: #2563eb; text-decoration: none; }}
    .meta a:hover {{ text-decoration: underline; }}
    iframe {{ width: 100%; border: 1px solid #e5e7eb; border-radius: 8px;
              margin-bottom: 1.5em; background: #fff; }}
    .chart-ts, .chart-tags {{ height: 500px; }}
    .chart-heat {{ height: 600px; }}
  </style>
</head>
<body>
  <h1>🛡️ USOM İnteraktif Zafiyet Panosu</h1>
  <p class="meta">
    Tarih aralığı: <strong>{start_date.strftime('%d.%m.%Y')} – {end_date.strftime('%d.%m.%Y')}</strong> ·
    Son güncelleme: <strong>{last_updated}</strong> ·
    Veri kaynağı: <a href="https://siberguvenlik.gov.tr">Siber Güvenlik Başkanlığı</a><br>
    <a href="https://github.com/emregulerr/usom-zafiyet-panosu">📦 GitHub repo</a> ·
    <a href="https://usom-zafiyet-panosu.streamlit.app/">🚀 Tam pano (Streamlit, filtreli)</a>
  </p>
  <iframe src="time_series_chart.html" class="chart-ts" title="Zaman serisi"></iframe>
  <iframe src="top_tags_chart.html" class="chart-tags" title="En çok etiket"></iframe>
  <iframe src="heatmap.html" class="chart-heat" title="Isı haritası"></iframe>
</body>
</html>
"""
    with open(os.path.join(save_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(index_html)
    print(f"İnteraktif HTML pano kaydedildi: {save_dir}/index.html")


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