(async () => {

  let count = 0;
  setInterval(() => {
    console.log(count);
    count = 0;
  }, 1000);

  while (true) {
    const res = await fetch('https://decent-auth.tn7.org/auth/login?type=oidc&oidc_provider=https://lastlogin.net');
    if (!res.ok) {
      throw new Error();
    }
    count++;
  }
})();
