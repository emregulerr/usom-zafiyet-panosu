import streamlit as st
import datetime
import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import time
import random
import threading
import locale
import base64
from main import fetch_all_vulnerabilities, normalize, save_vulnerabilities_to_csv

# --- Konfigürasyon ve Yardımcı Fonksiyonlar ---

st.set_page_config(layout="wide", page_title="USOM Zafiyet Panosu")

# Grafiklerdeki ay isimlerini Türkçeleştirmek için yerel ayarı ayarla
try:
    locale.setlocale(locale.LC_TIME, 'tr_TR.UTF-8')
except locale.Error:
    try:
        locale.setlocale(locale.LC_TIME, 'tr_TR')
    except locale.Error:
        st.warning("Türkçe yerel ayarı (locale) ayarlanamadı. Grafiklerdeki ay isimleri İngilizce olabilir.")

# Beklerken gösterilecek eğlenceli mesajlar listesi
FUN_MESSAGES = [
    "🛰️ Siber uzayda zafiyet avına çıkılıyor...",
    "🔑 API anahtarları doğrulanıyor, Matrix'e bağlanılıyor...",
    "🚚 Veri paketleri yola çıktı, birazdan masanızda...",
    "🎨 Grafikler için pikseller özenle boyanıyor...",
    "☕ Lütfen bekleyin, makine kahvesini tazeliyor...",
    "🤫 Sunuculara fısıldanıyor, sırlar ortaya çıkıyor...",
    "🤖 1'ler ve 0'lar hizaya getiriliyor...",
    "🛡️ Zafiyetler taranıyor, kalkanlar hazırlanıyor...",
    "📡 Sinyal güçlendiriliyor, sabrınız için teşekkürler...",
    "🍪 Byte'lar ayıklanıyor, en lezzetli olanlar seçiliyor...",
    "🕵️‍♂️ Gizli geçitler ve arka kapılar kontrol ediliyor...",
    "💻 Kod derleniyor, bug'lar eziliyor...",
    "📈 Verileriniz görsel bir şölene dönüştürülüyor...",
    "🔍 Zafiyetler inceleniyor, hackerlar için tuzaklar kuruluyor...",
    "🧩 Parçalar birleştiriliyor, bulmacanın sonuna yaklaşılıyor...",
    "🎉 Sonuçlar yolda, sabrınız için teşekkürler!",
    "🚀 Veri uzayına fırlatılıyor, geri sayım başladı...",
    "🧙‍♂️ Veri büyücüleri çalışıyor, sihirli dokunuşlar yapılıyor...",
    "🕰️ Zaman yolculuğu yapılıyor, geçmişe dönülüyor...",
    "🔄 Sonsuz döngüde bekleniyor, sabrınız için teşekkürler...",
    "🧪 Deney tüpleri karıştırılıyor, yeni zafiyetler keşfediliyor...",
    "📊 Grafikler çiziliyor, veriler dans ediyor...",
    "🧭 Yön bulma cihazları ayarlanıyor, doğru yolda ilerliyoruz...",
    "🧩 Zeka küpü çözülüyor, karmaşık veriler basitleştiriliyor..."
]

# En maliyetli işlem olan veri çekmeyi önbelleğe alıyoruz.
@st.cache_data(show_spinner=False)
def cached_fetch_data(start_date):
    API_URL = "https://www.usom.gov.tr/api/incident/index"
    return fetch_all_vulnerabilities(API_URL, start_date)

def generate_interactive_visuals(vulnerabilities, title_suffix=""):
    # Bu fonksiyon önceki versiyonla aynı, bir değişiklik yok.
    tags, date_counts = {}, {}
    for vuln in vulnerabilities:
        if vuln[1]:
            for tag in vuln[1].split("|"):
                tags[normalize(tag)] = tags.get(normalize(tag), 0) + 1
        if vuln[2]:
            date = vuln[2].split("T")[0]
            date_counts[date[:7]] = date_counts.get(date[:7], 0) + 1

    fig_ts, fig_tags, fig_heatmap = None, None, None
    if date_counts:
        sorted_date_counts = sorted(date_counts.items())
        months, counts = [item[0] for item in sorted_date_counts], [item[1] for item in sorted_date_counts]
        fig_ts, ax = plt.subplots(figsize=(12, 7))
        ax.plot(months, counts, marker='o')
        ax.set_title(f'Aya Göre Zafiyet Sayısı\n{title_suffix}')
        plt.setp(ax.get_xticklabels(), rotation=90)
        ax.grid(True)
        plt.tight_layout()
    if tags:
        sorted_tags = sorted(tags.items(), key=lambda x: x[1], reverse=True)[:10]
        df_tags = pd.DataFrame(sorted_tags, columns=['Etiket', 'Sayı'])
        fig_tags, ax = plt.subplots(figsize=(12, 8))
        sns.barplot(data=df_tags, x='Sayı', y='Etiket', palette='viridis', ax=ax)
        ax.set_title(f'En Çok Kullanılan 10 Etiket\n{title_suffix}')
        plt.tight_layout()

        tags_by_month = {}
        for vuln in vulnerabilities:
            if vuln[1] and vuln[2]:
                year_month = vuln[2].split("T")[0][:7]
                if year_month not in tags_by_month: tags_by_month[year_month] = {}
                for tag in vuln[1].split("|"):
                    tags_by_month[year_month][normalize(tag)] = tags_by_month[year_month].get(normalize(tag), 0) + 1
        top_10_tags = [tag for tag, count in sorted_tags]
        heatmap_data = pd.DataFrame(index=sorted(tags_by_month.keys()), columns=top_10_tags).fillna(0)
        for month, tags_in_month in tags_by_month.items():
            for tag in top_10_tags:
                heatmap_data.at[month, tag] = tags_in_month.get(tag, 0)
        fig_heatmap, ax = plt.subplots(figsize=(14, 10))
        sns.heatmap(heatmap_data.astype(int), cmap="YlGnBu", annot=True, fmt="d", ax=ax)
        ax.set_title(f'Türkiye Zafiyet Sıcaklık Haritası\n{title_suffix}')
        plt.tight_layout()
    return fig_ts, fig_tags, fig_heatmap

# Analiz işlemini yürütecek ve sonucu bir listeye koyacak fonksiyon
def analysis_thread_function(start_date, end_date, results_list):
    start_date_dt = datetime.datetime.combine(start_date, datetime.time.min)
    all_vulnerabilities = cached_fetch_data(start_date_dt)

    end_date_dt = datetime.datetime.combine(end_date, datetime.time.max)
    filtered_vulnerabilities = [v for v in all_vulnerabilities if start_date_dt.strftime("%Y-%m-%d") <= v.get("date", "")[:10] <= end_date_dt.strftime("%Y-%m-%d")]

    OUTPUT_DIR = "output"; os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv_path = os.path.join(OUTPUT_DIR, "vulnerabilities_data.csv")
    unique_vulnerabilities = save_vulnerabilities_to_csv(filtered_vulnerabilities, csv_path)

    if unique_vulnerabilities:
        df = pd.read_csv(csv_path)
        title_suffix = f"({start_date.strftime('%d.%m.%Y')} - {end_date.strftime('%d.%m.%Y')})"
        figs = generate_interactive_visuals(unique_vulnerabilities, title_suffix)
        results_list.append({'df': df, 'figs': figs, 'count': len(unique_vulnerabilities)})
    else:
        results_list.append(None)


# --- STREAMLIT ARAYÜZÜ ---

st.title("USOM İnteraktif Zafiyet Panosu")

st.sidebar.header("Filtreler")
default_start_date = datetime.date.today() - datetime.timedelta(days=30)
start_date = st.sidebar.date_input("Başlangıç Tarihi", default_start_date)
end_date = st.sidebar.date_input("Bitiş Tarihi", datetime.date.today())

st.sidebar.divider()
st.sidebar.markdown(
    "Geliştiren: **Emre Güler**",
    unsafe_allow_html=False,
)

github_svg = """
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
</svg>
"""
b64_svg = base64.b64encode(github_svg.encode('utf-8')).decode("utf-8")

st.sidebar.markdown(
    f"""
    <a href="https://github.com/emregulerr/usom-zafiyet-panosu" target="_blank" style="text-decoration: none; color: inherit; display: flex; align-items: center; height: 24px;">
        <img src="data:image/svg+xml;base64,{b64_svg}" style="height: 100%; width: auto; margin-right: 8px; max-width: 24px;">
        <span style="line-height: 24px;">GitHub Repo</span>
    </a>
    """,
    unsafe_allow_html=True,
)

if start_date > end_date:
    st.sidebar.error("Hata: Başlangıç tarihi, bitiş tarihinden sonra olamaz.")
else:
    results_container = []  # Arka plandaki işin sonucunu tutmak için

    # Analizi arka planda (thread) başlat
    analysis_thread = threading.Thread(
        target=analysis_thread_function,
        args=(start_date, end_date, results_container)
    )
    analysis_thread.start()

    # Geçici mesajlar için bir yer tutucu oluştur
    placeholder = st.empty()

    # Analiz bitene kadar eğlenceli mesajları döngüde göster
    while analysis_thread.is_alive():
        message = random.choice(FUN_MESSAGES)
        with placeholder.container():
            st.info(f"{message}")
        time.sleep(5)

    # Analiz bittiğinde (döngüden çıktığında) yer tutucuyu temizle
    placeholder.empty()

    # Sonuçları göster
    if results_container and results_container[0] is not None:
        result = results_container[0]
        df = result['df']
        fig_ts, fig_tags, fig_heatmap = result['figs']
        count = result['count']

        st.success(f"Analiz tamamlandı! Belirtilen aralıkta {count} adet eşsiz zafiyet bulundu.")
        st.header("Görsel Çıktılar")
        col1, col2 = st.columns(2)
        with col1:
            if fig_ts: st.pyplot(fig_ts)
        with col2:
            if fig_tags: st.pyplot(fig_tags)
        if fig_heatmap: st.pyplot(fig_heatmap)

        st.header("Zafiyet Verileri")
        st.dataframe(df)
    else:
        st.warning("Belirtilen tarih aralığında herhangi bir zafiyet bulunamadı.")