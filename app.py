"""
PHISHLENS - Modern Cybersecurity Dashboard
"Scan before you trust."
Hackathon Edition - Step 3: Domain & Brand Lookalike Intelligence
"""
import streamlit as st
from PIL import Image
import config
import detector

# 1. Page Configuration
st.set_page_config(
    page_title=f"{config.APP_NAME} | {config.TAGLINE}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 2. Modern Dark Cybersecurity SaaS Styling
CYBER_CSS = """
<style>
/* Main Background and Fonts */
.stApp {
    background-color: #070B14;
    color: #F8FAFC;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Header & Typography */
h1, h2, h3, h4, h5, h6 {
    color: #F8FAFC !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em;
}

/* Glassmorphism Card Containers */
.cyber-card {
    background: rgba(15, 23, 42, 0.65);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(56, 189, 248, 0.18);
    border-radius: 14px;
    padding: 24px;
    margin-bottom: 20px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    transition: border-color 0.25s ease, box-shadow 0.25s ease;
}

.cyber-card:hover {
    border-color: rgba(0, 240, 255, 0.4);
    box-shadow: 0 10px 36px 0 rgba(0, 240, 255, 0.08);
}

/* Brand Banner */
.brand-title {
    font-size: 2.8rem;
    font-weight: 900;
    background: linear-gradient(135deg, #00F0FF 0%, #38BDF8 50%, #818CF8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    display: inline-block;
    letter-spacing: 0.05em;
    margin: 0;
    padding: 0;
}

.brand-tagline {
    font-size: 1.15rem;
    color: #94A3B8;
    margin-top: 4px;
    margin-bottom: 16px;
    font-weight: 400;
}

.badge-pill {
    display: inline-flex;
    align-items: center;
    background: rgba(0, 240, 255, 0.1);
    border: 1px solid rgba(0, 240, 255, 0.3);
    color: #00F0FF;
    border-radius: 9999px;
    padding: 4px 14px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 12px;
}

/* Custom Cyber Button Styling */
div.stButton > button {
    background: linear-gradient(135deg, #0284C7 0%, #00F0FF 100%) !important;
    color: #041320 !important;
    font-weight: 700 !important;
    font-size: 1.05rem !important;
    letter-spacing: 0.03em !important;
    border: none !important;
    border-radius: 10px !important;
    padding: 12px 32px !important;
    width: 100% !important;
    box-shadow: 0 4px 20px rgba(0, 240, 255, 0.25) !important;
    transition: all 0.2s ease !important;
}

div.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 26px rgba(0, 240, 255, 0.45) !important;
}

div.stButton > button:active {
    transform: translateY(0px) !important;
}

/* Intelligence Key-Value Grid */
.intel-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px;
    margin-top: 14px;
}

.intel-item {
    background: rgba(15, 23, 42, 0.55);
    border: 1px solid rgba(56, 189, 248, 0.14);
    border-radius: 8px;
    padding: 12px 16px;
}

.intel-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #94A3B8;
    margin-bottom: 4px;
}

.intel-value {
    font-size: 0.95rem;
    font-weight: 600;
    color: #F8FAFC;
    word-break: break-all;
}

/* Security Signal Cards */
.signal-card {
    background: rgba(15, 23, 42, 0.7);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 12px;
    display: flex;
    align-items: flex-start;
    gap: 14px;
    transition: transform 0.15s ease;
}

.signal-card:hover {
    transform: translateX(4px);
}

.signal-card-high {
    border-left: 5px solid #EF4444;
    border-top: 1px solid rgba(239, 68, 68, 0.2);
    border-right: 1px solid rgba(239, 68, 68, 0.2);
    border-bottom: 1px solid rgba(239, 68, 68, 0.2);
}

.signal-card-medium {
    border-left: 5px solid #F59E0B;
    border-top: 1px solid rgba(245, 158, 11, 0.2);
    border-right: 1px solid rgba(245, 158, 11, 0.2);
    border-bottom: 1px solid rgba(245, 158, 11, 0.2);
}

.signal-card-low {
    border-left: 5px solid #38BDF8;
    border-top: 1px solid rgba(56, 189, 248, 0.2);
    border-right: 1px solid rgba(56, 189, 248, 0.2);
    border-bottom: 1px solid rgba(56, 189, 248, 0.2);
}

.badge-high {
    background: rgba(239, 68, 68, 0.15);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.35);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
}

.badge-medium {
    background: rgba(245, 158, 11, 0.15);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.35);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
}

.badge-low {
    background: rgba(56, 189, 248, 0.15);
    color: #38BDF8;
    border: 1px solid rgba(56, 189, 248, 0.35);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
}

/* Domain Intelligence Alert Cards */
.domain-alert-high {
    background: rgba(239, 68, 68, 0.08);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-left: 5px solid #EF4444;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 10px;
}

.domain-alert-official {
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-left: 5px solid #10B981;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 10px;
}

/* Clean Reassurance Box */
.clear-card {
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.3);
    border-left: 5px solid #10B981;
    border-radius: 10px;
    padding: 16px 20px;
    color: #D1FAE5;
}

/* Error Box */
.error-card {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-left: 5px solid #EF4444;
    border-radius: 10px;
    padding: 16px 20px;
    color: #FECACA;
    margin-top: 18px;
}

/* Sidebar Styling */
section[data-testid="stSidebar"] {
    background-color: #0A0F1D !important;
    border-right: 1px solid rgba(56, 189, 248, 0.12) !important;
}

/* Tabs */
div[data-baseweb="tab-list"] {
    background: rgba(15, 23, 42, 0.8) !important;
    border-radius: 10px !important;
    padding: 6px !important;
    border: 1px solid rgba(56, 189, 248, 0.15) !important;
}

button[data-baseweb="tab"] {
    color: #94A3B8 !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
}

button[aria-selected="true"] {
    color: #00F0FF !important;
    background: rgba(56, 189, 248, 0.15) !important;
}
</style>
"""
st.markdown(CYBER_CSS, unsafe_allow_html=True)

# 3. Sidebar (Product Identity, System Status & Privacy Guarantee)
with st.sidebar:
    st.markdown(
        """
        <div style="text-align: center; padding: 10px 0;">
            <div style="font-size: 2.2rem; margin-bottom: 4px;">🛡️</div>
            <div style="font-size: 1.3rem; font-weight: 800; color: #00F0FF; letter-spacing: 0.05em;">PHISHLENS</div>
            <div style="font-size: 0.82rem; color: #94A3B8;">Cybersecurity Intelligence</div>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown("---")
    
    st.markdown("### ⚡ System Status")
    st.markdown(
        """
        <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.88rem;">
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #94A3B8;">URL Engine:</span>
                <span style="color: #10B981; font-weight: 600;">● Active</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #94A3B8;">Domain & Brand:</span>
                <span style="color: #10B981; font-weight: 600;">● Active (Step 3)</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #94A3B8;">QR & UPI:</span>
                <span style="color: #94A3B8; font-weight: 600;">○ Standby (Step 4)</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #94A3B8;">Risk Verifier:</span>
                <span style="color: #94A3B8; font-weight: 600;">○ Standby</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: #94A3B8;">Privacy Mode:</span>
                <span style="color: #10B981; font-weight: 600;">Zero-Leak Hashing</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    st.markdown("---")
    st.markdown("### 🔒 Privacy Policy")
    st.info("Raw query parameter values are never displayed or stored. All parameter values are securely hashed before logging.")

    st.markdown("---")
    st.caption("🏆 Hackathon Project • Version 0.3.0")

# 4. Main Banner
st.markdown(
    """
    <div>
        <div class="badge-pill">⚡ 3-Second Security Check</div>
        <br/>
        <h1 class="brand-title">PHISHLENS</h1>
        <div class="brand-tagline">Scan before you trust.</div>
    </div>
    """,
    unsafe_allow_html=True
)

# Initialize Session State for preset links
if "input_url_val" not in st.session_state:
    st.session_state.input_url_val = ""

# 5. Dual Input Modes: URL or QR Image
st.markdown(
    """
    <div class="cyber-card">
        <div style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-bottom: 6px;">
            Target Selection
        </div>
        <div style="font-size: 0.9rem; color: #94A3B8; margin-bottom: 16px;">
            Inspect a suspicious URL directly or upload a QR-code image captured from a payment desk or message.
        </div>
    """,
    unsafe_allow_html=True
)

tab_url, tab_qr = st.tabs(["🌐 Analyze URL", "📷 Scan QR Code"])

target_input = ""
target_type = "URL"
uploaded_file = None

with tab_url:
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    target_input = st.text_input(
        "Enter Link / URL:",
        value=st.session_state.input_url_val,
        placeholder="https://example.com/login or paste any suspicious web address",
        help="Paste the link you received via SMS, WhatsApp, or email."
    )
    
    # Quick chip suggestions for user testing convenience
    st.markdown("<div style='font-size: 0.8rem; color: #64748B;'>Example test links (Click to populate):</div>", unsafe_allow_html=True)
    chip_row1 = st.columns(3)
    with chip_row1[0]:
        if st.button("🔗 incometax.gov.in (Official)", key="chip_gov"):
            st.session_state.input_url_val = "https://incometax.gov.in"
            st.rerun()
    with chip_row1[1]:
        if st.button("⚠️ paytmm.example (Typosquat)", key="chip_typo"):
            st.session_state.input_url_val = "https://paytmm.example"
            st.rerun()
    with chip_row1[2]:
        if st.button("🚨 sbi-secure-login.example (Lookalike)", key="chip_lookalike"):
            st.session_state.input_url_val = "https://sbi-secure-login.example"
            st.rerun()

    chip_row2 = st.columns(3)
    with chip_row2[0]:
        if st.button("🛑 sbi-login.attacker.example (Subdomain)", key="chip_sub"):
            st.session_state.input_url_val = "https://sbi-login.attacker.example"
            st.rerun()
    with chip_row2[1]:
        if st.button("🔤 pаytm.example (Unicode Homoglyph)", key="chip_homoglyph"):
            st.session_state.input_url_val = "https://pаytm.example"
            st.rerun()
    with chip_row2[2]:
        if st.button("🛡️ example.com/sbi/login (Brand in path)", key="chip_path"):
            st.session_state.input_url_val = "https://example.com/sbi/login"
            st.rerun()

with tab_qr:
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload QR Code Image:",
        type=["png", "jpg", "jpeg", "webp"],
        help="Upload a screenshot or photo of a QR code (UPI payment QR, website link QR, etc.)."
    )
    if uploaded_file is not None:
        try:
            uploaded_image = Image.open(uploaded_file)
            st.image(uploaded_image, caption="Uploaded QR Code Preview", width=220)
            target_input = f"[QR Image: {uploaded_file.name}]"
            target_type = "QR"
        except Exception as e:
            st.error(f"Could not load image: {e}")

st.markdown("</div>", unsafe_allow_html=True)

# 6. Action Button
st.markdown("<div style='height: 4px;'></div>", unsafe_allow_html=True)
col_btn, _ = st.columns([1, 2])
with col_btn:
    analyze_clicked = st.button("⚡ ANALYZE TARGET", use_container_width=True)

# 7. Analysis Trigger and Output
if analyze_clicked:
    if not target_input.strip() and uploaded_file is None:
        st.warning("⚠️ Please provide a URL or upload a QR image before clicking Analyze.")
    elif target_type == "QR":
        # QR Analysis placeholder for upcoming step
        st.markdown(
            """
            <div class="cyber-card" style="border-left: 5px solid #00F0FF; margin-top: 20px;">
                <div style="color: #00F0FF; font-weight: 700; font-size: 1.15rem; margin-bottom: 8px;">
                    🛡️ QR Analysis Engine Standby
                </div>
                <div style="color: #CBD5E1; font-size: 0.95rem;">
                    QR payload extraction and UPI deep analysis will be integrated in <strong>Step 4</strong>.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        # Step 3: Full URL & Domain Security Analysis
        result = detector.analyze_target(target_input, target_type="URL")
        
        if result.get("status") == "error":
            # Friendly error handling without exposing stack traces
            st.markdown(
                f"""
                <div class="error-card">
                    <div style="font-weight: 700; font-size: 1.05rem; margin-bottom: 4px;">
                        ⚠️ Analysis Notice
                    </div>
                    <div style="font-size: 0.92rem;">
                        {result.get('error_message', 'Invalid URL format provided.')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            intel = result["url_intelligence"]
            dom_intel = result.get("domain_intelligence", {})
            signals = result["signals"]
            sig_count = result["signals_count"]

            # ==========================================
            # SECTION 1: URL INTELLIGENCE
            # ==========================================
            st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
            st.markdown(
                """
                <div class="cyber-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(56, 189, 248, 0.15); padding-bottom: 12px; margin-bottom: 16px;">
                        <div style="font-size: 1.25rem; font-weight: 800; color: #00F0FF; letter-spacing: 0.04em;">
                            🌐 URL INTELLIGENCE
                        </div>
                        <span class="badge-pill" style="margin-bottom: 0;">Verified Structure</span>
                    </div>
                """,
                unsafe_allow_html=True
            )

            # Key-Value Intelligence Grid
            params_display = ", ".join(intel['query_param_names']) if intel['query_param_names'] else "None"
            proto_color = "#10B981" if intel['scheme'] == "HTTPS" else "#F59E0B"
            ip_badge = f" <span class='badge-medium' style='margin-left: 6px;'>{intel['ip_version']}</span>" if intel['is_ip'] else ""

            st.markdown(
                f"""
                <div class="intel-grid">
                    <div class="intel-item">
                        <div class="intel-label">Original URL</div>
                        <div class="intel-value" style="font-family: monospace; font-size: 0.88rem; color: #38BDF8;">
                            {result['original_url']}
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Normalized Hostname</div>
                        <div class="intel-value" style="font-family: monospace;">
                            {intel['normalized_hostname']}{ip_badge}
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Protocol</div>
                        <div class="intel-value" style="color: {proto_color};">
                            {intel['scheme']} (Port {intel['port']})
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Path</div>
                        <div class="intel-value" style="font-family: monospace;">
                            {intel['path']}
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Registrable Domain</div>
                        <div class="intel-value">
                            {intel['registrable_domain'] or 'N/A'}
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Query Parameters (Privacy Protected)</div>
                        <div class="intel-value" style="font-size: 0.88rem;">
                            <strong>{intel['query_param_count']}</strong> parameter(s) detected:
                            <span style="color: #94A3B8; font-family: monospace;">{params_display}</span>
                            <div style="font-size: 0.72rem; color: #64748B; margin-top: 2px;">
                                🔒 Parameter values are never exposed or logged.
                            </div>
                        </div>
                    </div>
                </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # ==========================================
            # SECTION 2: DOMAIN INTELLIGENCE (NEW STEP 3)
            # ==========================================
            st.markdown(
                """
                <div class="cyber-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(56, 189, 248, 0.15); padding-bottom: 12px; margin-bottom: 16px;">
                        <div style="font-size: 1.25rem; font-weight: 800; color: #38BDF8; letter-spacing: 0.04em;">
                            🏢 DOMAIN INTELLIGENCE
                        </div>
                        <span class="badge-pill" style="margin-bottom: 0;">Brand & Homoglyph Engine</span>
                    </div>
                """,
                unsafe_allow_html=True
            )

            # Domain breakdown items
            brand_match_text = f"<span style='color: #10B981;'>✓ Official {dom_intel.get('official_brand_name')} Domain</span>" if dom_intel.get('is_official_brand') else "<span style='color: #94A3B8;'>None (Third-Party / Unofficial)</span>"
            impersonation_text = f"<span style='color: #EF4444;'>🚨 Impersonating {dom_intel.get('impersonated_brand')}</span>" if dom_intel.get('impersonated_brand') else "<span style='color: #10B981;'>None</span>"
            
            # Check typosquatting in domain signals
            typo_sig = next((s for s in dom_intel.get("signals", []) if s.get("name") == "Typosquatting detected"), None)
            typo_text = f"<span style='color: #EF4444;'>⚠️ Suspected (Targeting {typo_sig.get('brand')})</span>" if typo_sig else "<span style='color: #10B981;'>None</span>"

            # Check homoglyph & punycode
            if dom_intel.get("has_homoglyphs"):
                homoglyph_text = "<span style='color: #EF4444;'>🚨 Confusable Characters Detected</span>"
            else:
                homoglyph_text = "<span style='color: #10B981;'>None (Clean Latin)</span>"

            if dom_intel.get("is_punycode"):
                puny_text = f"<span style='color: #F59E0B;'>Yes ({dom_intel.get('decoded_punycode')})</span>"
            else:
                puny_text = "<span style='color: #94A3B8;'>None (Standard ASCII)</span>"

            st.markdown(
                f"""
                <div class="intel-grid">
                    <div class="intel-item">
                        <div class="intel-label">Subdomain</div>
                        <div class="intel-value" style="font-family: monospace;">
                            {dom_intel.get('subdomain') or 'None'}
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Registrable Domain (SLD + TLD)</div>
                        <div class="intel-value" style="font-family: monospace; color: #00F0FF;">
                            {dom_intel.get('registrable_domain') or 'N/A'}
                        </div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Trusted Brand Match</div>
                        <div class="intel-value">{brand_match_text}</div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Brand Impersonation</div>
                        <div class="intel-value">{impersonation_text}</div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Typosquatting</div>
                        <div class="intel-value">{typo_text}</div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Unicode / Homoglyph</div>
                        <div class="intel-value">{homoglyph_text}</div>
                    </div>
                    <div class="intel-item">
                        <div class="intel-label">Punycode (IDN)</div>
                        <div class="intel-value">{puny_text}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

            # Specific Domain Alert or Reassurance banner
            if dom_intel.get("is_official_brand"):
                st.markdown(
                    f"""
                    <div class="domain-alert-official" style="margin-top: 14px;">
                        <div style="font-weight: 700; color: #10B981; font-size: 0.98rem; display: flex; align-items: center; gap: 8px;">
                            <span>✓</span> Verified Official Brand Domain
                        </div>
                        <div style="font-size: 0.88rem; color: #A7F3D0; margin-top: 4px;">
                            This domain matches the registered official digital portal for <strong>{dom_intel.get('official_brand_name')}</strong>.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            elif dom_intel.get("impersonated_brand") or typo_sig or dom_intel.get("has_homoglyphs"):
                st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
                if dom_intel.get("impersonated_brand"):
                    st.markdown(
                        f"""
                        <div class="domain-alert-high">
                            <div style="font-weight: 700; color: #EF4444; font-size: 0.98rem; display: flex; align-items: center; gap: 8px;">
                                <span>🚨</span> Brand Impersonation Alert
                            </div>
                            <div style="font-size: 0.88rem; color: #FECACA; margin-top: 4px;">
                                This domain closely imitates <strong>{dom_intel.get('impersonated_brand')}</strong> but is registered under an unofficial domain name.
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                if dom_intel.get("has_homoglyphs"):
                    st.markdown(
                        """
                        <div class="domain-alert-high">
                            <div style="font-weight: 700; color: #EF4444; font-size: 0.98rem; display: flex; align-items: center; gap: 8px;">
                                <span>🚨</span> Unicode Homoglyph Attack
                            </div>
                            <div style="font-size: 0.88rem; color: #FECACA; margin-top: 4px;">
                                Confusable characters detected in the domain name designed to visually deceive victims.
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.markdown(
                    """
                    <div class="clear-card" style="margin-top: 14px;">
                        <div style="font-weight: 700; font-size: 0.95rem; display: flex; align-items: center; gap: 8px;">
                            <span>✓</span> No Brand Impersonation Detected
                        </div>
                        <div style="font-size: 0.85rem; margin-top: 3px; color: #A7F3D0;">
                            The domain does not imitate any protected banking, wallet, or government brand.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            st.markdown("</div>", unsafe_allow_html=True)

            # ==========================================
            # SECTION 3: SECURITY SIGNALS
            # ==========================================
            st.markdown(
                """
                <div class="cyber-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(56, 189, 248, 0.15); padding-bottom: 12px; margin-bottom: 16px;">
                        <div style="font-size: 1.25rem; font-weight: 800; color: #F8FAFC; letter-spacing: 0.04em;">
                            ⚡ SECURITY SIGNALS
                        </div>
                """,
                unsafe_allow_html=True
            )

            # Signals Summary Counter
            st.markdown(
                f"""
                        <div style="display: flex; gap: 8px;">
                            <span class="badge-high">{sig_count['high']} High</span>
                            <span class="badge-medium">{sig_count['medium']} Medium</span>
                            <span class="badge-low">{sig_count['low']} Low</span>
                        </div>
                    </div>
                """,
                unsafe_allow_html=True
            )

            if not signals:
                st.markdown(
                    """
                    <div class="clear-card">
                        <div style="font-weight: 700; font-size: 1.05rem; display: flex; align-items: center; gap: 8px;">
                            <span>🛡️</span> All Signals Clear
                        </div>
                        <div style="font-size: 0.88rem; margin-top: 4px; color: #A7F3D0;">
                            No suspicious structural anomalies, lookalike patterns, or brand impersonation detected.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                for sig in signals:
                    severity = sig.get("severity", "low").lower()
                    if severity == "high":
                        icon = "🚨"
                        card_class = "signal-card-high"
                        badge_class = "badge-high"
                    elif severity == "medium":
                        icon = "⚠️"
                        card_class = "signal-card-medium"
                        badge_class = "badge-medium"
                    else:
                        icon = "ℹ️"
                        card_class = "signal-card-low"
                        badge_class = "badge-low"

                    st.markdown(
                        f"""
                        <div class="signal-card {card_class}">
                            <div style="font-size: 1.5rem; line-height: 1;">{icon}</div>
                            <div style="flex-grow: 1;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                    <div style="font-weight: 700; font-size: 0.98rem; color: #F8FAFC;">
                                        {sig['name']}
                                    </div>
                                    <span class="{badge_class}">{severity.upper()}</span>
                                </div>
                                <div style="font-size: 0.88rem; color: #CBD5E1; line-height: 1.4;">
                                    {sig['description']}
                                </div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            st.markdown("</div>", unsafe_allow_html=True)

# 8. Clean Dashboard Footer
st.markdown("<div style='margin-top: 50px;'></div>", unsafe_allow_html=True)
st.markdown(
    """
    <div style="text-align: center; color: #64748B; font-size: 0.8rem; border-top: 1px solid rgba(56, 189, 248, 0.1); padding-top: 20px;">
        PHISHLENS Cybersecurity Dashboard • "Scan before you trust." • Built for Hackathon
    </div>
    """,
    unsafe_allow_html=True
)
