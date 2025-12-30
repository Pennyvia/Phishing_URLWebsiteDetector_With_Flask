  check.addEventListener('click', function () {
    chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
      const tab = tabs[0];
      const response = await fetch('http://localhost:5000/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({url: tab.url}),
      });
      const prediction = await response.json();

      if (prediction.prediction === 'Legitimate') {
        resultElement.innerHTML = 'Legitimate <span style="color: green;">&#9679;</span> Safe: Enjoy your browsing!';
      } else {
        resultElement.innerHTML = 'Phishing <span style="color: red;">&#9679;</span> Alert: This website has characteristics commonly associated with phishing. Do not enter any sensitive information on the site.';
      }
    });
});
