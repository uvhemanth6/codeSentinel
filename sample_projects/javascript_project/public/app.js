function showMessage(text) {
  document.getElementById('msg').innerHTML = text;
  console.log('shown', text);
  debugger;
}

async function loadProfile(id) {
  const res = await fetch('/profile/' + id);
  const data = await res.json();
  showMessage(data.bio);
}
