// DEMO FILE - intentionally vulnerable.
// Showcases the review tool. Every issue here is deliberate.

const API_TOKEN = "ghp_demoToken1234567890abcd";

function renderComment(userInput) {
  // XSS: unescaped input written straight into the DOM
  document.getElementById("comments").innerHTML = userInput;
}

function runUserCode(code) {
  // Code injection via eval
  return eval(code);
}

function loadConfig() {
  return JSON.parse(localStorage.getItem("config"));
}

function submit(form) {
  const xhr = new XMLHttpRequest();
  // Credentials and tokens sent over plain HTTP
  xhr.open("POST", "http://api.internal.example.com/v1/submit");
  xhr.send(form);
}

module.exports = { renderComment, runUserCode, loadConfig, submit };