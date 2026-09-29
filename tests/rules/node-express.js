const express = require('express');
const { exec, execFile } = require('child_process');
const cp = require('child_process');
const run = require('child_process').exec;
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const serialize = require('node-serialize');
const ejs = require('ejs');
const _ = require('lodash');

const app = express();

app.get('/users', (req, res) => {
  // ruleid: vulnscan.js.sql-injection
  db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  // ruleid: vulnscan.js.sql-injection
  db.all(`SELECT * FROM users WHERE id = ${req.params.id}`);
  // ok: vulnscan.js.sql-injection
  db.query('SELECT * FROM users WHERE name = ?', [req.query.name]);
  // ok: vulnscan.js.sql-injection
  cache.get(req.query.key);
  // ok: vulnscan.js.sql-injection
  db.all(`SELECT * FROM users WHERE id = ${parseInt(req.params.id)}`);
  // ruleid: vulnscan.js.sql-injection
  knex('users').whereRaw('name = ' + req.body.name);
  // ruleid: vulnscan.js.sql-injection
  prisma.$queryRawUnsafe(`SELECT * FROM t WHERE x = '${req.body.x}'`);
});

app.post('/login', async (req, res) => {
  // ruleid: vulnscan.js.nosql-injection
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  // ok: vulnscan.js.nosql-injection
  const u2 = await User.findOne({ username: String(req.body.username) });
  // ok: vulnscan.js.nosql-injection
  const local = users.find((u) => u.name === req.body.username);
  res.json(user);
});

app.get('/ping', function (req, res) {
  // ruleid: vulnscan.js.command-injection
  exec('ping -c 1 ' + req.query.host);
  // ruleid: vulnscan.js.command-injection
  cp.execSync(`nslookup ${req.query.host}`);
  // ok: vulnscan.js.command-injection
  execFile('ping', ['-c', '1', req.query.host]);
  // ruleid: vulnscan.js.command-injection
  cp.spawn('sh', ['-c', 'ls ' + req.query.dir]);
  // ok: vulnscan.js.command-injection
  /^[a-z]+$/.exec(req.query.host);
  // ruleid: vulnscan.js.command-injection
  run('ping -c 2 ' + req.body.address, () => {});
});

app.get('/calc', (req, res) => {
  // ruleid: vulnscan.js.code-injection
  const result = eval(req.query.expr);
  // ruleid: vulnscan.js.code-injection
  const green = eval(req.query.green, 10);
  // ruleid: vulnscan.js.template-injection
  const html = ejs.render(req.body.template, {});
  res.json({ result, length: html.length });
});

app.get('/download', (req, res) => {
  // ruleid: vulnscan.js.path-traversal
  fs.readFile(path.join(__dirname, 'uploads', req.query.file), (e, d) => res.end(d));
  // ok: vulnscan.js.path-traversal
  fs.readFile(path.join(__dirname, 'uploads', path.basename(req.query.file)), () => {});
  // ruleid: vulnscan.js.path-traversal
  res.sendFile(__dirname + '/public/' + req.params.name);
  // ok: vulnscan.js.path-traversal
  res.sendFile(req.params.name, { root: __dirname + '/public' });
});

app.get('/preview', async (req, res) => {
  // ruleid: vulnscan.js.ssrf
  const r = await axios.get(req.query.url);
  // ok: vulnscan.js.ssrf
  await fetch(`https://api.example.com/items/${req.params.id}`);
  // ruleid: vulnscan.js.ssrf
  await fetch(`http://${req.query.host}/health`);
  res.json(r.data);
});

app.get('/go', (req, res) => {
  // ruleid: vulnscan.js.open-redirect
  res.redirect(req.query.next);
  // ok: vulnscan.js.open-redirect
  res.redirect('/profile?tab=' + req.query.tab);
});

app.get('/hello', (req, res) => {
  // ruleid: vulnscan.js.reflected-xss
  res.send('<h1>Hello ' + req.query.name + '</h1>');
  // ok: vulnscan.js.reflected-xss
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
  // ok: vulnscan.js.reflected-xss
  res.json({ name: req.query.name });
});

app.post('/profile', (req, res) => {
  // ruleid: vulnscan.js.unsafe-deserialization
  const obj = serialize.unserialize(req.cookies.profile);
  // ruleid: vulnscan.js.regex-injection
  const re = new RegExp(req.query.pattern);
  // ruleid: vulnscan.js.prototype-pollution
  config[req.body.section][req.body.key] = req.body.value;
  res.json(obj);
});

router.get('/koa', async (ctx) => {
  // ruleid: vulnscan.js.sql-injection
  await db.query('DELETE FROM notes WHERE id = ' + ctx.params.id);
});

function renderFromHash() {
  const target = document.getElementById('out');
  // ruleid: vulnscan.js.dom-xss
  target.innerHTML = decodeURIComponent(location.hash.slice(1));
  // ok: vulnscan.js.dom-xss
  target.textContent = location.hash.slice(1);
}

function Comment({ body }) {
  // ruleid: vulnscan.js.unsafe-html-render
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

function SafeComment({ body }) {
  // ok: vulnscan.js.unsafe-html-render
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;
}
