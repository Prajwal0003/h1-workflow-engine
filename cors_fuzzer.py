import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://experiences.priceline.com"

COOKIE_STRING = "datadome=guNJV4CuJ6mWFZlbdzhfQl5UCqkmlvbQvUGlY5ZQlwUT_3NYKMCbYCKjpDDe8dpcLS_z6YE~12i_jFC9ZbCZnIhucffiuKzPYAkZOySkQufxXiVA8rxQjG4POYI9B4cY; x-viator-tapersistentcookie=9318f507-e5c5-466c-9038-b0f0b7011d2d; SEM_PARAMS=%7B%7D; SEM_MCID=42853; EXTERNAL_SESSION_ID=; LAST_TOUCH_SEM_MCID=42853; XSRF-TOKEN=555997bc-a3d5-46eb-9a33-13ee07ba8ba8; ORION_SESSION=Ac5m65myye2pVYlGN%2Bl8cw%3D%3D%7Cy0xV0u0izQAeuzYfM%2Bfeo67qSYKWNhx3sBjtglcGLJA%2FfZGjz7LdCVEKKIgLH%2FDljPlM7V6%2FEBltKxbE%2FCF5CHGTNtGrl%2FzHXyVUiwI1BHjhIQQ1knw2oUg2GiKQnmjFsLwy0NCD00Dp2pIyGYNkFpJoc%2BLWOLaB1ud1j2%2FXu05rvWxU5HM7UnzTvVwgvmUaCds0kF5s0UXZftX13NIpRF7IoJz3UgX8zH58Vf70oqOzZ9gn3FIHN5qcFkwDBsAdHAUoRXifLQHMcDBj9EdMtRhMXZ%2FRWb19RLYMvAFubb%2B226O1iqWcuqvEpGMpo2NQRmp42XjbBZUhg3XdzBPbAvufXhBCxt2L457FCYQLDQaH4gCUwrI7aqAbqJMlzOVruw9zE5wz5EufQ26r14G4%2F10GMPe1amr8rcElO4erp6HuoW6Gzut%2FgSwxgLtY8BTWl8Fi1VIxwOZa2kLsqugSpeLvc98MTq3nkxTwPMZx7cv1pt2ekHWdDYkNcwm0a4Ps09IN4aWOX3HAYs2FQfKwebD5SQ2lPYm9axOh016H3xqPWLbG4K9Bd4KUSF6QMRA73q7YUyNflCF412tXTVExAIOXT6KXKSH5%2FQHhwOMo7NKRpSjoB1hdjiIPmUx%2BiHAqNWYTvdThMXkCuuXDDOAKo29WJ9XFv7UdklBgbR6xhsX%2FfksssA0J4s1GNSxNeW2yp2%2BUjg0Cawvvg1fEZ%2FNnSn0SLLx7L1IRJhMx5FOKfL6n1iE9HdMtllabNRA7KlaGNjIhjplyo%2Brf7SUmRnajfK4CmqgWpsBNa%2FBkjaECUoxINgSSYj5ZrXSJojr9foX5yI5FS8GO9gyBkv%2BBRkqSWZa%2BQE5Ifv9OpavCJcnxREd8J5CAae4q0uSMp%2FyM8gZAnBARVPmowvnEf6c34cGD414xr5AmBKkSB5mdpfLHmRzPhBjGOu1qoEIPQp7C25JD8ytO0NJlZ4X1tG9FTJPfictGd6LuQTrBV5KpwHpRzNlqqesLrL1jwCVbTwO8X%2FQ7eX9FxR8%2BZ4NU6opOU64uZK4QOYZTbD63pryws%2BhG1re4WkNIFKQZAaPQvaEOIztY7dKSnFCp8O%2BRviJc9nzL2mIxUg1ReLWWTeNnSbPMvSV%2BqNo5fLetfeGzwtCbYiH5HrLbW%2F3agTf5wx1vwFJfCXXaQnPk8LrOuZrET5tHlcWhDua2Ti9SZX0PCitdPAJZP4c1PSYLyadkSJrsT%2BNidP%2FC4ziKjvXw24AMdklfnaWdF5fDQPhCvQsZB3hMJGZdcSEprmDzxHzCIceoX94sxd00h%2BtNxD6E7qOaZvv3%2FSQUzHla6mdpIvInZR4jF0auaSVsXA7puMFhLf%2BxVwZvRdTM4r3uwmr4eTaxh9WkytnRHfIFdlKP9B6IRjTpD7Z2iSZBiokn9EUylgdfpYOqMzNrEIOd5nWVVDjvcaI9UDEk%2FFDrS3Poi3S98xyXBGQrEi%2FSl%2BOY9ftWnNPAozFIcbanozOUvZbW%2FScoTpFdMJUGEQVaj7o%2BM8xB24eF5vB8isIWqWp%2BCvrSxLg6UZyDmkhzIs%2BD%2FJuNGl0bEzpkl4KTx2FULebyA%2BIyKfHesvykDrXW8uRsuJaCto6px7E1%2FzCJ%2FKN1pjazPo%2BynjAUx8kqxs%2FsLRmie0ca2tYOFOswsWbHwgV173I1WTSH01Z%2FNjdOKC3fYDT%2FlOJImTMsk%2BX1O7S0PcaZM0u2yoIQp22%2BrHlZtXDbCD7Iw6M%2FLklmu5HoQaPKC1BDFp3YRPn2LBIgG9pyzoFra%2FPNkx6e1%2F5UyUsQVMZcisYMaUYOPNgKzDSaWRIItyBLAXYToGbENH8TCoWaxWEeq8lYUMj88M%2F7HonX4VxMgNmf715QdmMcI5rDMj92FdPz51rtHWW6SB67KeLVZZslQoSv5ZVdZjG6ZUDb7DQYQ5mk3qifVmgUROAcsvdFsFF3wpsWY%2FZENyAeB73VSyU1%2Fw8DzBMJR%2Flp0QtMa%2BsmtOLoLtJ3OghCJvPcAePcx17cboK0loucvGK%2BQFJWac9nkf%2B9Nul9vaxkBO7ML2%2FSIS5tZzpbIOAX0F%2BW8wPs8aCgMqYl9rUUdAjeW%2FMUrewbezNiYFy7xZA8JvVxok88pgXuh6DeR7Sh6Mq6NKol7dL3HhOaBOJyOWvabjc7nhm7EQKx4FhNL1GNqNTvqJxw8w80edSN0EsgaRKgpkXuRu5JD8w0xZKkXckB3km1FMgmUcPt2reUL8o3TdNNqff0NdQAp%2BajHaPQ9Yfg2iZ%2BtoQZutzi%2FHko7kHctob5yd0Xp9aFhZDgmSMy%7CiHDFOLMMydM%3D%3As0Ry9%2BakKhNEMwAI8RHLfsm2lv%2BrjpuDvv%2B4YXTOxyU%3D; orion_first_touch_logged_in=false; ORION_SESSION_REQ=8CF86A03%3AE748_0A28060B%3A01BB_6A1ABF08_2000CC2%3A702E7%7C8CF86A00%3A234E_0A280B46%3A01BB_6A1ABF00_1FEF7DD%3AABBDD%7C8CF86A00%3A234E_0A280B46%3A01BB_6A1ABF00_1FEF7DD%3AABBDD; profilingBeaconSession=dCp0pn8e9mEEbwYCGwHZ%2Fg%3D%3D%7Cj8I8XHFYkcTKD588nfTkjo6ApPd5%2FZd6%2BeWwsAk4sEEvV%2BOeXMC5WQ6fpoXm12nuBSoxKKnGwes%3D%7CHvj%2FlkDcM0I%3D%3AusMf72WPxUZ6bXQlwpaG0S0W4pYSqIEoPtTjrY5BVAA%3D; profilingInAuthSession=SmxyxjXroGY%2Bh80Pa4Pa8Q%3D%3D%7CYMcoM9pnu8qRAGMBHqwFPpVQ3anlH070HA%2BeD82mNCpLQRqXRdL9zoBWNjnDRNvDr7exF1zAofjx0qpJxDXkS6kSlTKv5p8zBXdmrI13tOTUMMuvAw%3D%3D%7COnEaNZ%2FiLFE%3D%3A4LELA%2BxpYCQPHFf1Hoq37JB6cz73dES8mj713bmCUn8%3D; _ga_MGF06LSQF0=GS2.1.s1780137559$o1$g1$t1780137728$j60$l0$h0; _ga=GA1.1.2091119819.1780137560; REFERER_PAGE_REQUEST_ID=8CF86A00:234E_0A280B46:01BB_6A1ABF00_1FEF7DD:ABBDD; OptanonConsent=isGpcEnabled=0&datestamp=Sat+May+30+2026+06%3A42%3A09+GMT-0400+(Eastern+Daylight+Time)&version=202402.1.0&browserGpcFlag=0&isIABGlobal=false&hosts=&landingPath=NotLandingPage&groups=SSPD_BG%3A1%2CC0005%3A1%2CC0004%3A1%2CC0001%3A1%2CC0002%3A1%2CC0003%3A1&AwaitingReconsent=false; _gcl_au=1.1.1684993247.1780137566; _bcnctkn=d490016161194ce1edccf2293a3438ee3490; _cc=AdUsxEVHAJ0F2%2F%2FJfWIi15Ei; lastRskxRun=1780137730503; rskxRunCookie=0; rCookie=zzby4mq0fodr8e8w6xb9qmps7y3ij; vid=v20260530063933170b6c64; Referral=CLICKID=&WEBENTRYTIME=5%2F30%2F2026%2006%3A41%3A45&ID=DIRECT&PRODUCTID=&SOURCEID=DT; PL_CINFO=0lpDLSE2fhJIIfj3H5a0JZJ0XWK4arao~1780137703~v2; SITESERVER=ID=0lpDLSE2fhJIIfj3H5a0JZJ0XWK4arao; __cf_bm=tc1Yck_EhmITLX2UOsm4qLDf_fvyZUXi_tnoXE9ps28-1780137589.8653772-1.0.1.1-nQA7erq.jOU72t3e7ClkQ7D9JHpdYwPFusG3w5.0uoti905xK73FBqAq5HGuXDWTyoNM8Gdxlp59qnWF4h0HTBpJcCO7cha6SoI2vi5dyz3OzbMN3ajHcgDkG6poKG0vO0V4NyEFGBb7HsYgj9vK9g; forterToken=7401a9d8e63f4fe1a6549624ec32daba_1780137703113__UDF43-m4_17ck; _pxvid=e2256e41-5c13-11f1-9e93-7099f7875454; pxcts=yMUF2N5me1scpFTxJ5AxrJBy3/TKGQXxxSKDLf/dWhY=:Vf8HtjDiP5uiqB4GSMJCtbTHAIeKX/eJDn8QeuFy3mj1Yz8c6pI4ATsz340XxhKXvm4c1YYgc0s0YrSHGMWEICgasoMPrtmkh57rxpgMaMhw3EDPGqSWhEj6S8RDt79IseiYB/GQ9AIrPm2bDSdKPp4W1NiSrwrlyQRGKqjZDcWtjxL9nRXAPz1qimPTocy/; _pxde=ede452b8a4a5e89587307547e217e32b3e65a721399dd801361c59844ce937a0:eyJ0aW1lc3RhbXAiOjE3ODAxMzc3MjQ4MjcsImZfa2IiOjB9; OptanonConsent=isGpcEnabled=0&datestamp=Sat+May+30+2026+06%3A41%3A48+GMT-0400+(Eastern+Daylight+Time)&version=202601.1.0&browserGpcFlag=0&isIABGlobal=false&hosts=&landingPath=NotLandingPage&groups=SSPD_BG%3A1%2CC0005%3A1%2CC0004%3A1%2CC0001%3A1%2CC0002%3A1%2CC0003%3A1&AwaitingReconsent=false; _ga_DC72C50JN6=GS2.1.s1780137588$o1$g1$t1780137728$j31$l0$h0; cf_clearance=vg1xQjyVVedHRhs5N8SlNPbu6wn7lzvIqcwceEretsA-1780137590-1.2.1.1-FDfYak5tgbn523DOKCWNh2Rqh.jzuaR.E5dUHeX._IeqgYAPSGo1t9L29JQWV3CATScwGLyErtyo_0u.F3oR0d_OjfYlI5TVqaThFlqwK7Vlz3Jk0V8e2pozSnmeC06Q59frgne1dUPDxPYYXzuhYbbz1Ez727l3t4RqvTy6HfQHcIkvpvUgwOXTW9vK4jVU_sgwx3urRZcnGT6lITcEkfYXQ9RwS_7cjbXEP0odJLphW2T1wKt2gBJpWvlmT.ZJvd3VLHUg0we9l5iOAgAQioOKedAtZe9TtERJ9aRg49PEqhVkWWleeKFUGdAtkBEpatwHp5.Eq7rjBdHuS3toZw; utag_main=v_id:019e7877f81800166f1f23da08c905046001a00900ac2$_sn:1$_se:2$_ss:0$_st:1780139503605$ses_id:1780137588761%3Bexp-session$_pn:2%3Bexp-session$dc_visit:1$dc_event:2%3Bexp-session$cookiesyncran:true%3Bexp-session$dc_region:ap-east-1%3Bexp-session; __pxvid=e2c9eca6-5c13-11f1-aa73-1ebdfb300a76; _px3=9c386f26ed06555353effad5b81df0af54044c3ac14534868b77eb9a2beaffd3:NERQGizL73xT+NosEk3VzseATeU4+AhM5vXvzsi/l9+/YW29rFm4tDg8blJDopZBvbrmTpFE6/qxrXzbl4QvMA==:1000:J2Cl/Uz9HVYT+tvnI6gRzslpl/dBC8ELBol40YpZe2FNUW80trlvH/DNaJpGypGE6JFRBu6BEHkyRrB/erKYG/1SyuGusremho6u1pNBcIG7x8ckJ2zU823GDfaF/ZqA75Up3uurTYEFepedlNLhDuq1kCOHivcCBTznHSC+h8NJ+usG8OvONrnP53VVcYwaEY693NNun28aJljBahjRziFlIROr72T1ATaw4wKoipDklxD2kGj3VJaQehK6nXnHzNGcOuG1KZwWHD9dXkIaToUETXNnLihJmuU01qvHX8+fpO+qYBFFXMo3tkIM8lO3BbIbE4lnJWRap6TJfsH0/954GqrooyOPn8px5FEgg5RqnTDmG/4hxVSdx4mXXDALXhnpxKE3GTj5XFi9Hc5+H5i0v72hU1xGqY6xlkOyz/y5fhkkeDsu8qlB8U2cghrLrwrsd3EHfcQ9lCzHWqpi38Yg5o69iml6yQITi4X3AXM=; _px2=eyJ1IjoiMjYzNTYxZDAtNWMxNC0xMWYxLTg4MmItNjEzNTMxYWQxZWRiIiwidiI6ImUyMjU2ZTQxLTVjMTMtMTFmMS05ZTkzLTcwOTlmNzg3NTQ1NCIsInQiOjE3ODAxMzgwMDk4MjQsImgiOiJiMDE3OTljNjVjZGUwNDk4ZTc3ZmVhMjAyZGRlMjQ2YjdiZDkxZWIwYmFmOTlkNTIwMzI1NGRhMmEzZThjODVjIn0=; _fbp=fb.1.1780137589256.17520536342264492.Bg; FCCDCF=%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%5B%5B32%2C%22%5B%5C%22ad4e97ea-4efe-42cb-bd3e-75e12827c16e%5C%22%2C%5B1780137590%2C243000000%5D%5D%22%5D%5D%5D; ftr_blst_1h=1780137590495; AMP_TOKEN=%24NOT_FOUND; _gid=GA1.2.191460041.1780137701; _dc_gtm_UA-2975581-1=1; _scid=_jJcyw3jquRRXQahzMg469ZHGEGCmr8f; _scid_r=_jJcyw3jquRRXQahzMg469ZHGEGCmr8f; _rdt_uuid=1780137706207.4cf6b253-e724-46ec-9eed-8f855dfc946f; _uetsid=2839c9505c1411f18760e9aa1a8c9afb; _uetvid=2839d0105c1411f1a85fefc310068a08; _pin_unauth=dWlkPU5ESTBaV1EzWWpBdFl6aG1ZaTAwT1Roa0xXRTNaVGd0TVRjd056RXpaVGRpWTJFMw; FCNEC=%5B%5B%22AKsRol8EeK6wVm2hFMS8_A_aCgvpIZsherH3Y5vrrrY6FRce0GDoN2f_JtfsQwVN87JXsh8VnTCJx5yqCMnOSy84frkE1X4TmdJn79GLmBmiRfp4u1ceBiW1B4iDAkQ9FIgnLjuvkmLzp0hjgA2E9QcMq_PhoWalsg%3D%3D%22%5D%5D; _sctr=1%7C1780113600000; _tpauid=thackerone053@gmail.com; cto_bundle=qyM1jV84U2ZlaGRXMG5qbk9haiUyQkdZZ2NYUiUyRkxKQXo5cDRUNGN0ekI0azNRTGUwdEppQ1U0dHBXd1B1cFlpcUEyTDElMkJYVllKZm5wSFN3Ymd6dmZRVjczVGYxMFJac2xVTG5oc2djUnU0NlolMkZiREglMkJuRlphbzhsQUl6OHgzJTJGWTF6VDRTTTZTZGRLUGxEZk4zNTk3RXAwVWR4SnclM0QlM0Q; __gads=ID=8c5834574dad07d4:T=1780137710:RT=1780137710:S=ALNI_MZpnDFfQzUd34xqhubhbzbFSRsyyQ; __gpi=UID=00001439fdba593e:T=1780137710:RT=1780137710:S=ALNI_MbLrMNJoOG73Ua3Gp6cIFk-3mZ2Dw; __eoi=ID=12eb3c4961108d2a:T=1780137710:RT=1780137710:S=AA-AfjbbVopaxdGYIAqwEzNyQ1sg"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Origin": "https://evil.com",
    "Cookie": COOKIE_STRING,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Priority": "u=0, i",
    "TE": "trailers"
}

# Common sensitive endpoints
WORDLIST = [
    "", "/", "/api/v1/user", "/api/user", "/api/me", "/api/profile",
    "/v1/users/me", "/user/details", "/account", "/profile",
    "/api/bookings", "/api/reservations", "/api/trips",
    "/graphql", "/api/graphql", "/swagger-ui.html"
]

print(f"[*] Fuzzing {BASE_URL} for sensitive endpoints...")
print(f"[*] Sending 'Origin: https://evil.com' to test CORS reflection.\n")

for path in WORDLIST:
    target = f"{BASE_URL}{path}"
    try:
        resp = requests.get(target, headers=HEADERS, verify=False, timeout=5)
        
        if resp.status_code != 404: # Ignore 404s
            print(f"[+] Found Endpoint: {target} (Status: {resp.status_code})")
            
            # Check for CORS vulnerability
            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if allow_origin == "https://evil.com" and allow_creds == "true":
                print(f"    [!!!] VULNERABLE TO CORS: {target}")
                print(f"    [!!!] Response size: {len(resp.text)} bytes")
                if resp.status_code == 200:
                    print(f"    [!!!] Data snippet: {resp.text[:100]}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error on {target}: {e}")

print("\n[*] Fuzzing complete.")
