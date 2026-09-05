# Internet Lead search — operator settings

The portal can find leads for a customer's sales form automatically. Provider
selection and keys are environment variables on the hosting platform
(Koyeb → the app → Environment variables):

```
SEARCH_ENGINE=auto       # auto | serper | serpapi | bing | ddg   (default auto)
SEARCH_API_KEY=...       # the Serper.dev or SerpAPI key (only needed for those two)
LEAD_AUTO=1              # let the platform search on its own every 6 hours
LEAD_AUTO_HOURS=6        # optional: override the interval
```

Provider order in `auto` mode: Serper → SerpAPI → free scraping (DuckDuckGo +
Bing HTML). The free engines need no key but cloud/DC IPs are frequently
throttled or served region-specific noise, so a run can come back empty; the
portal then shows a clear "no results right now, try again" message instead of
failing. Retries across engines + multiple user-agents and a junk/content filter
(social apps, dictionaries, government/news sites, foreign-language noise,
adult content) run automatically in every mode.

Search respects each customer's `searchEnabled` toggle in the sales form.