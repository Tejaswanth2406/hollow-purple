module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'method_not_allowed', message: 'Only GET is supported.' });
    return;
  }

  res.writeHead(302, {
    Location: 'https://github.com/Tejaswanth2406/hollow-purple/archive/refs/heads/main.zip',
  });
  res.end();
};
