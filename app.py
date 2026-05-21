import streamlit as st
import datetime
import os
import base64
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from main import API_URL, fetch_all_vulnerabilities, normalize, save_vulnerabilities_to_csv

# --- Konfigürasyon ---

st.set_page_config(layout="wide", page_title="USOM Zafiyet Panosu", page_icon="🛡️")
OUTPUT_DIR = "output"
CSV_FILENAME = "vulnerabilities_data.csv"


# --- Veri Katmanı ---

@st.cache_data(ttl=3600, show_spinner=False)
def cached_fetch_data(start_date: datetime.date, api_url: str = API_URL):
    """USOM/Siber Güvenlik Başkanlığı API'sinden veriyi çeker. 1 saat cache.

    `api_url` cache key'inin parçası — USOM_API_URL değişirse otomatik invalidate.
    """
    start_date_dt = datetime.datetime.combine(start_date, datetime.time.min)
    return fetch_all_vulnerabilities(api_url, start_date_dt)


def build_dataframe(raw_vulns, start_date: datetime.date, end_date: datetime.date) -> pd.DataFrame:
    """Ham API verisini filtreleyip normalleştirilmiş bir DataFrame'e dönüştürür."""
    start_s = start_date.strftime("%Y-%m-%d")
    end_s = end_date.strftime("%Y-%m-%d")
    filtered = [v for v in raw_vulns if start_s <= v.get("date", "")[:10] <= end_s]

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv_path = os.path.join(OUTPUT_DIR, CSV_FILENAME)
    unique = save_vulnerabilities_to_csv(filtered, csv_path)
    if not unique:
        return pd.DataFrame(columns=["Başlık", "Etiketler", "Tarih"])

    df = pd.DataFrame(unique, columns=["Başlık", "Etiketler", "Tarih"])
    df["Tarih"] = pd.to_datetime(df["Tarih"], errors="coerce")
    df["Ay"] = df["Tarih"].dt.strftime("%Y-%m")
    df["Etiket Listesi"] = df["Etiketler"].fillna("").apply(
        lambda s: [normalize(t) for t in s.split("|") if t]
    )
    return df


def filter_by_tags(df: pd.DataFrame, selected_tags: list[str]) -> pd.DataFrame:
    if not selected_tags:
        return df
    mask = df["Etiket Listesi"].apply(lambda tags: any(t in tags for t in selected_tags))
    return df[mask]


# --- Görselleştirme (Plotly) ---

def fig_time_series(df: pd.DataFrame) -> go.Figure | None:
    if df.empty:
        return None
    counts = df.groupby("Ay").size().reset_index(name="Zafiyet Sayısı").sort_values("Ay")
    fig = px.line(
        counts, x="Ay", y="Zafiyet Sayısı", markers=True,
        title="Aya Göre Zafiyet Sayısı",
    )
    fig.update_layout(xaxis_tickangle=-45, hovermode="x unified", height=420)
    return fig


def fig_top_tags(df: pd.DataFrame, top_n: int = 10) -> tuple[go.Figure | None, list[str]]:
    tags = df.explode("Etiket Listesi")
    tags = tags[tags["Etiket Listesi"].astype(bool)]
    if tags.empty:
        return None, []
    top = tags["Etiket Listesi"].value_counts().head(top_n).reset_index()
    top.columns = ["Etiket", "Sayı"]
    fig = px.bar(
        top, x="Sayı", y="Etiket", orientation="h",
        title=f"En Çok Kullanılan {top_n} Etiket",
        color="Sayı", color_continuous_scale="Viridis",
    )
    fig.update_layout(yaxis={"categoryorder": "total ascending"}, height=460, coloraxis_showscale=False)
    return fig, top["Etiket"].tolist()


def fig_heatmap(df: pd.DataFrame, top_tags: list[str]) -> go.Figure | None:
    if df.empty or not top_tags:
        return None
    exploded = df.explode("Etiket Listesi")
    exploded = exploded[exploded["Etiket Listesi"].isin(top_tags)]
    if exploded.empty:
        return None
    pivot = (
        exploded.groupby(["Ay", "Etiket Listesi"]).size()
        .unstack(fill_value=0).reindex(columns=top_tags, fill_value=0)
        .sort_index()
    )
    fig = px.imshow(
        pivot, text_auto=True, aspect="auto",
        color_continuous_scale="YlGnBu",
        labels=dict(x="Etiket", y="Ay", color="Sayı"),
        title="Aylık Zafiyet Yoğunluğu (Isı Haritası)",
    )
    fig.update_layout(height=520)
    return fig


# --- UI ---

st.title("🛡️ USOM İnteraktif Zafiyet Panosu")
st.caption("USOM tarafından yayınlanan zafiyet bildirimlerinin canlı analiz panosu")

with st.sidebar:
    st.header("Filtreler")

    today = datetime.date.today()
    preset = st.radio(
        "Hızlı Aralık",
        ["Son 7 gün", "Son 30 gün", "Son 90 gün", "Özel"],
        index=1,
        horizontal=False,
    )
    preset_days = {"Son 7 gün": 7, "Son 30 gün": 30, "Son 90 gün": 90}

    if preset == "Özel":
        start_date = st.date_input("Başlangıç Tarihi", today - datetime.timedelta(days=30))
        end_date = st.date_input("Bitiş Tarihi", today)
    else:
        start_date = today - datetime.timedelta(days=preset_days[preset])
        end_date = today
        st.caption(f"📅 {start_date} → {end_date}")

    st.divider()
    st.markdown("Geliştiren: **Emre Güler**")

    github_svg = """
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
    </svg>
    """
    b64_svg = base64.b64encode(github_svg.encode("utf-8")).decode("utf-8")
    st.markdown(
        f"""
        <a href="https://github.com/emregulerr/usom-zafiyet-panosu" target="_blank"
           style="text-decoration: none; color: inherit; display: flex; align-items: center; height: 24px;">
            <img src="data:image/svg+xml;base64,{b64_svg}"
                 style="height: 100%; width: auto; margin-right: 8px; max-width: 24px;">
            <span style="line-height: 24px;">GitHub Repo</span>
        </a>
        """,
        unsafe_allow_html=True,
    )

if start_date > end_date:
    st.error("Başlangıç tarihi, bitiş tarihinden sonra olamaz.")
    st.stop()

with st.spinner("🛰️ USOM'dan veriler çekiliyor (önbellek 1 saat geçerli)..."):
    raw = cached_fetch_data(start_date)

df = build_dataframe(raw, start_date, end_date)

if df.empty:
    st.warning("Belirtilen tarih aralığında zafiyet bulunamadı.")
    st.stop()

# --- Etiket filtresi (canlı süzme) ---
all_tags = sorted({t for tags in df["Etiket Listesi"] for t in tags})
selected_tags = st.sidebar.multiselect(
    "Etikete göre filtrele",
    options=all_tags,
    help="Bir veya birden fazla etiket seçerek tabloyu ve grafikleri süzebilirsin.",
)
df_view = filter_by_tags(df, selected_tags)

# --- KPI Kartları ---
total = len(df_view)
days = max((end_date - start_date).days, 1)
daily_avg = total / days

if not df_view.empty:
    top_tag_series = df_view.explode("Etiket Listesi")["Etiket Listesi"]
    top_tag_series = top_tag_series[top_tag_series.astype(bool)]
    top_tag = top_tag_series.value_counts().idxmax() if not top_tag_series.empty else "—"
    unique_tag_count = top_tag_series.nunique()
    last_date = df_view["Tarih"].max().strftime("%d.%m.%Y") if df_view["Tarih"].notna().any() else "—"
else:
    top_tag, unique_tag_count, last_date = "—", 0, "—"

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Toplam Zafiyet", f"{total:,}")
k2.metric("Günlük Ortalama", f"{daily_avg:.1f}")
k3.metric("Eşsiz Etiket", f"{unique_tag_count:,}")
k4.metric("En Popüler Etiket", top_tag)
k5.metric("Son Kayıt", last_date)

st.divider()

# --- Grafikler ---
ts_fig = fig_time_series(df_view)
tags_fig, top_tag_names = fig_top_tags(df_view)
heat_fig = fig_heatmap(df_view, top_tag_names)

c1, c2 = st.columns(2)
with c1:
    if ts_fig:
        st.plotly_chart(ts_fig, use_container_width=True)
with c2:
    if tags_fig:
        st.plotly_chart(tags_fig, use_container_width=True)

if heat_fig:
    st.plotly_chart(heat_fig, use_container_width=True)

# --- Veri Tablosu + İndirme ---
st.subheader("📋 Zafiyet Verileri")
display_df = df_view[["Başlık", "Etiketler", "Tarih"]].copy()
display_df["Tarih"] = display_df["Tarih"].dt.strftime("%Y-%m-%d")
st.dataframe(display_df, use_container_width=True, hide_index=True)

csv_bytes = display_df.to_csv(index=False).encode("utf-8")
st.download_button(
    "⬇️ CSV olarak indir",
    data=csv_bytes,
    file_name=f"usom_zafiyet_{start_date}_{end_date}.csv",
    mime="text/csv",
)
