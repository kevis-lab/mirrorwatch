# MirrorWatch

Přepracovaná desktopová aplikace pro vyhledávání pravděpodobných zrcadel a imitací webových domén.

## Co přibylo

- čisté pracovní rozhraní s bočním panelem a prioritizací nálezů;
- složené skóre: vizuální podobnost, podobnost textu, sdílená IP a přesměrování;
- srozumitelný verdikt: `VYSOKÉ RIZIKO`, `PODEZŘELÉ`, `PŘESMĚROVÁNÍ` nebo `NÍZKÁ SHODA`;
- průběžné výsledky, náhledy a export do XLSX;
- ochrana proti kontrolám neveřejných/privátních IP adres a proti neomezenému řetězení redirectů.

## Spuštění

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

Poznámka: pyppeteer při prvním spuštění může stáhnout svůj Chromium runtime. Aplikace nejdříve použije lokálně nainstalovaný Chrome nebo Edge, pokud je nalezne.
