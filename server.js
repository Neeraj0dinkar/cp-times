const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let articles = [
  {
    id: "cv-launch",
    title: "CP Times: Fast, factual and fearless news for a new India",
    slug: "cp-times-fast-factual-and-fearless",
    category: "India",
    excerpt: "Welcome to CP Times — a modern digital news destination covering India, world affairs, business, technology, sports and entertainment.",
    body: "CP Times is built around clear reporting, useful context and a fast digital experience. This launch article is sample content that can be replaced from the admin dashboard or a future CMS.",
    author: "CP Times Desk",
    publishedAt: new Date().toISOString(),
    image: "",
    featured: true
  },
  {
    id: "india-story",
    title: "India's biggest stories, explained clearly",
    slug: "indias-biggest-stories-explained",
    category: "India",
    excerpt: "Follow the developments shaping cities, communities, policy and public life.",
    body: "This is placeholder article content. Connect your newsroom workflow or CMS to publish real reporting.",
    author: "CP Times Desk",
    publishedAt: new Date().toISOString(),
    image: "",
    featured: false
  },
  {
    id: "tech-story",
    title: "AI and technology trends to watch",
    slug: "ai-and-technology-trends-to-watch",
    category: "Technology",
    excerpt: "From artificial intelligence to digital products, technology is changing everyday life.",
    body: "This is placeholder article content for the Technology category.",
    author: "CP Times Tech Desk",
    publishedAt: new Date().toISOString(),
    image: "",
    featured: false
  }
];

app.get("/api/articles", (req, res) => {
  const category = req.query.category;
  const q = (req.query.q || "").toLowerCase();
  let result = articles;
  if (category) result = result.filter(a => a.category.toLowerCase() === category.toLowerCase());
  if (q) result = result.filter(a => `${a.title} ${a.excerpt} ${a.body}`.toLowerCase().includes(q));
  res.json(result.sort((a,b) => new Date(b.publishedAt) - new Date(a.publishedAt)));
});

app.get("/api/articles/:slug", (req, res) => {
  const article = articles.find(a => a.slug === req.params.slug);
  if (!article) return res.status(404).json({error:"Article not found"});
  res.json(article);
});

// Demo CMS endpoints. Protect these with authentication before production use.
app.post("/api/admin/articles", (req, res) => {
  const {title, category, excerpt, body, author="CP Times Desk", image="", featured=false} = req.body;
  if (!title || !category || !body) return res.status(400).json({error:"title, category and body are required"});
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  const article = {id: String(Date.now()), title, slug, category, excerpt, body, author, image, featured, publishedAt:new Date().toISOString()};
  articles.unshift(article);
  res.status(201).json(article);
});

app.delete("/api/admin/articles/:id", (req,res) => {
  const before = articles.length;
  articles = articles.filter(a => a.id !== req.params.id);
  if (articles.length === before) return res.status(404).json({error:"Article not found"});
  res.json({ok:true});
});

app.get("/sitemap.xml", (req,res) => {
  const base = `${req.protocol}://${req.get("host")}`;
  const urls = ["", "/article.html?slug=cp-times-fast-factual-and-fearless", "/category.html?name=India", "/category.html?name=World", "/category.html?name=Business", "/category.html?name=Technology", "/category.html?name=Sports", "/category.html?name=Entertainment"];
  res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls.map(u=>`<url><loc>${base}${u}</loc></url>`).join("")}</urlset>`);
});

app.get("/{*splat}", (req,res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, "0.0.0.0", () => console.log(`CP Times running on port ${PORT}`));