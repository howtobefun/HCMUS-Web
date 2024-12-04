import express from "express";
import session from "express-session";
import ejs from "ejs";
import livereload from "livereload";
import connectLiveReload from "connect-livereload";
import path from "path";
import { fileURLToPath } from "url";
import { getArticles } from "./getArticles.js";
import { getArticles1 } from "./getArticles-1.js";
import { connectDB } from "./db.js";
import NodeCache from "node-cache";
import articleRoute from "./routes/articleRoute.js";
import userRoute from "./routes/userRoute.js";
import loginRegisterRoutes from "./strategies/local-strategy.js";
import passport from "./config/passport.js";
export const PassportSetup = passport;

const cache = new NodeCache({ stdTTL: 300 });

// Create __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const liveReloadServer = livereload.createServer();
liveReloadServer.watch([
  path.join(__dirname, "views"),
  path.join(__dirname, "public"),
]);

const app = express();

// Set EJS as the view engine
app.set("view engine", "ejs");

// Set the views directory
app.set("views", path.join(__dirname, "views"));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Add livereload to the middleware stack
app.use(connectLiveReload());

liveReloadServer.server.once("connection", () => {
  setTimeout(() => {
    liveReloadServer.refresh("/");
  }, 100);
});

// Routes
app.get("/", (req, res) => {
  const articles = getArticles();
  const categories = [
    ...new Set(articles.flatMap((article) => article.categories)),
  ];

  res.render("pages/HomePage", {
    title: "Trang chủ",
    categories,
    articles,
  });
});

app.use("/api/articles", articleRoute);
app.use("/api/users", userRoute);
app.use("/auth", loginRegisterRoutes);

// Modified article route with caching
app.get("/article/:id", async (req, res) => {
  try {
    const articleId = req.params.id;
    const cacheKey = `article_${articleId}`;

    // Check cache first
    const cachedArticle = cache.get(cacheKey);
    if (cachedArticle) {
      return res.render("pages/ArticlePage", cachedArticle);
    }

    // Get article by ID
    const response = await getArticles1(articleId);

    if (!response.success) {
      return res.status(404).send(response.error);
    }

    const article = response.data;
    const articleData = {
      title: article.name,
      article,
    };

    // Save to cache
    cache.set(cacheKey, articleData);

    res.render("pages/ArticlePage", articleData);
  } catch (error) {
    console.error("Route handler error:", error);
    res.status(500).send("Server error");
  }
});

const startServer = async () => {
  try {
    await connectDB();

    app.listen(3000, () => {
      console.log("Server listening on port 3000");
    });
  } catch (error) {
    console.error("Server startup error:", error);
    process.exit(1);
  }
};

startServer();
