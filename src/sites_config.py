"""The 10 websites of our lab: 5 NORMAL + 5 HACKED (simulation only).
A 'hacked' site looks normal in the browser, but a malicious module on its
server secretly leaks stolen data through DNS tunneling to its own C2 domain."""

GROUP_IP = {"normal": "172.28.0.21", "hacked": "172.28.0.22"}   # the two web-server containers

SITES = [
    # ---------------- 5 NORMAL websites ----------------
    dict(id="freshmart", name="FreshMart Grocery", domain="freshmart.test", hacked=False, c2=None,
         emoji="🛒", color="#16a34a", tagline="Fresh groceries delivered to your door",
         items=["Free delivery over $30", "Farm-fresh vegetables", "Same-day delivery slots"],
         form="Sign in to your account"),
    dict(id="dailynews", name="Daily News Today", domain="dailynews.test", hacked=False, c2=None,
         emoji="📰", color="#2563eb", tagline="Breaking stories, every hour",
         items=["World and local headlines", "Live sports scores", "Opinion and analysis"],
         form="Subscribe to our newsletter"),
    dict(id="travelbuddy", name="TravelBuddy Blog", domain="travelbuddy.test", hacked=False, c2=None,
         emoji="✈️", color="#0891b2", tagline="Stories and tips from around the world",
         items=["Budget travel guides", "Hidden beaches and trails", "Packing checklists"],
         form="Join our travel club"),
    dict(id="sunriseschool", name="Sunrise School Portal", domain="sunriseschool.test", hacked=False, c2=None,
         emoji="🎓", color="#7c3aed", tagline="Students, parents and teachers in one place",
         items=["Timetables and results", "Homework and notices", "Parent-teacher meetings"],
         form="Student login"),
    dict(id="weatherwise", name="WeatherWise", domain="weatherwise.test", hacked=False, c2=None,
         emoji="⛅", color="#0ea5e9", tagline="Accurate forecasts for your city",
         items=["7-day forecast", "Rain and storm alerts", "Air-quality index"],
         form="Get weather alerts"),
    # ---------------- 5 HACKED websites ----------------
    dict(id="gamezone", name="GameZone Free Games", domain="gamezone.test", hacked=True, c2="gz-stats.test",
         emoji="🎮", color="#dc2626", tagline="Play 500+ free games online",
         items=["Action and puzzle games", "Daily tournaments", "No download needed"],
         form="Create your player account"),
    dict(id="couponking", name="CouponKing Deals", domain="couponking.test", hacked=True, c2="ck-track.test",
         emoji="🏷️", color="#ea580c", tagline="Save up to 80% with verified coupons",
         items=["Top store coupons", "Cash-back offers", "Deal alerts"],
         form="Sign in to claim deals"),
    dict(id="snapshare", name="SnapShare Photos", domain="snapshare.test", hacked=True, c2="ss-sync.test",
         emoji="📷", color="#db2777", tagline="Share your photos with friends",
         items=["Unlimited photo albums", "Private sharing links", "Free cloud backup"],
         form="Log in to your albums"),
    dict(id="jobhub", name="JobHub Careers", domain="jobhub.test", hacked=True, c2="jh-metrics.test",
         emoji="💼", color="#b45309", tagline="Find your next job in minutes",
         items=["Thousands of openings", "Resume builder", "Interview tips"],
         form="Upload resume / log in"),
    dict(id="softupdate", name="SoftUpdate Downloads", domain="softupdate.test", hacked=True, c2="su-cdn.test",
         emoji="💾", color="#4b5563", tagline="Free software and driver updates",
         items=["Verified downloads", "Driver updater", "Security patches"],
         form="Sign in to download"),
]

BY_ID = {s["id"]: s for s in SITES}
BY_DOMAIN = {s["domain"]: s for s in SITES}
SITE_IPS = {s["domain"]: GROUP_IP["hacked" if s["hacked"] else "normal"] for s in SITES}
