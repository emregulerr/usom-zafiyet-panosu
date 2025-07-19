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

# --- CONFIGURATION ---
API_URL = "https://www.usom.gov.tr/api/incident/index"

# File/Directory Paths
OUTPUT_DIR = "output"
IMAGES_DIR = os.path.join(OUTPUT_DIR, "images")
OUTPUT_CSV_FILENAME = "vulnerabilities_data.csv"

# API Rate Limiting
REQUESTS_PER_MINUTE = 40
REQUESTS_PER_SECOND = 20
DELAY_SECOND = 1 / REQUESTS_PER_SECOND

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

    :param api_url: API URL'si
    :param page: Çekilecek sayfa numarası
    :param date_gte: Bu tarihten sonra çekilecek zafiyetler
    :return: JSON formatında zafiyet verileri
    """
    params = {"page": page, "per-page": 50}
    if date_gte:
        params["date_gte"] = date_gte
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        time.sleep(DELAY_SECOND)
        return response.json()
    except requests.RequestException as e:
        print(f"API'den veri alınırken hata oluştu: {e}")
        return None

def fetch_all_vulnerabilities(api_url, date_gte):
    """
    API'den belirli bir tarihten itibaren tüm zafiyet verilerini çeker.

    :param api_url: API URL'si
    :param date_gte: Bu tarihten sonra çekilecek zafiyetler
    :return: Tüm zafiyet verilerinin listesi
    """
    vulnerabilities = []
    current_page = 1
    total_requests = 0
    start_time = time.time()
    print(f"{date_gte.strftime('%Y-%m-%d')} tarihinden itibaren zafiyetler alınıyor...")

    while True:
        if total_requests >= REQUESTS_PER_MINUTE:
            elapsed_time = time.time() - start_time
            if elapsed_time < 60:
                time_to_wait = 60 - elapsed_time
                print(f"Rate limit aşıldı: {time_to_wait:.2f} saniye bekleniyor")
                time.sleep(time_to_wait)
            total_requests = 0
            start_time = time.time()

        page_data = fetch_vulnerabilities(api_url, current_page, date_gte.strftime("%Y-%m-%d"))
        if page_data and page_data.get("models"):
            vulnerabilities.extend(page_data.get("models", []))
            current_page += 1
            total_requests += 1
        else:
            break

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

    print("\nİşlem tamamlandı.")

if __name__ == "__main__":
    main()