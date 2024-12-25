import express from "express";
import cache from "../../config/cache.js";
import { getArticlesByPageWithSort} from "../../services/articleService.js";
import { getCategories } from "../../services/categoryService.js";
import { getTags } from "../../services/tagService.js";
import { findUser } from "../../services/userService.js";

const router = express.Router();

router.get("/newest", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    // Create timeout promise
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Request timeout")), 5000)
    );

    // Run queries in parallel with timeout
    const result = await Promise.race([
      Promise.all([getArticlesByPageWithSort(page, 12, "publishedDate", -1), getCategories(), getTags()]),
      timeout,
    ]);

    if (!req.isAuthenticated()) {
      console.log("User not authenticated");
    }

    const userId = req.user?._id;
    const user = req.user || (userId && (await findUser(userId))) || null;

    const [articlesResponse, categoriesResponse, tagsResponse] = result;

    // find author name for each article
    for (let i = 0; i < articlesResponse.data.length; i++) {
      const article = articlesResponse.data[i];
      const authors = await Promise.all(
        article.author.map((author) => findUser(author))
      );
      article.authorNames = authors.map((author) => author.name);
    }

    const pageData = {
      title: "Mới nhất",
      articles: articlesResponse.data,
      categories: categoriesResponse.data,
      tags: tagsResponse.data,
      pagination: articlesResponse.pagination,
      user: user,
    };

    res.render("pages/NewestPage", pageData);
  } catch (error) {
    console.error("Newest route error:", error);
    res.status(500).send("Server error");
  }
});

export default router;
