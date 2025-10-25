chrome.storage.local.get("lastUrl", data => {
  document.getElementById("last").innerText = data.lastUrl
    ? "Last URL: " + data.lastUrl
    : "No URL yet.";
});
document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.local.get(['lastURL','lastScore'], function(data){
        document.getElementById('url').innerText = data.lastURL || "No URL detected";
        const scoreEl = document.getElementById('threatScore');
        scoreEl.innerText = data.lastScore !== undefined ? data.lastScore : "0";

        if(data.lastScore < 30) scoreEl.className = 'score low';
        else if(data.lastScore < 70) scoreEl.className = 'score medium';
        else scoreEl.className = 'score high';
    });

    // Optional: rescan button
    document.getElementById('rescan').addEventListener('click', () => {
        chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            const url = tabs[0].url;
            const score = calculateThreatScore(url);
            document.getElementById('url').innerText = url;
            const scoreEl = document.getElementById('threatScore');
            scoreEl.innerText = score;
            if(score < 30) scoreEl.className = 'score low';
            else if(score < 70) scoreEl.className = 'score medium';
            else scoreEl.className = 'score high';
        });
    });
});
fetch("http://127.0.0.1:8000/api/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url }),
})
.then(res => res.json())
.then(data => chrome.storage.local.set({
  lastURL: url,
  lastScore: data.threat_score
}));
