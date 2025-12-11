const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

//MONGO CONNECTION
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Connection Error:", err.message));


//USER MODEL
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model("User", userSchema);


//PRODUCT MODEL 
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { 
    type: String, 
    enum: ["dog", "cat", "bird", "fish", "other"],
    required: true 
  },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  imageUrl: { type: String },
  stock: { type: Number, default: 50 },
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
});

const Product = mongoose.model("Product", productSchema);


//JWT VERIFY MIDDLEWARE 
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];

  if (!authHeader) return res.status(401).send("No token provided");

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send("Invalid token");

    req.userId = decoded.userId;
    next();
  });
};


//REGISTER 
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).send("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();
    res.status(201).send("User registered successfully");

  } catch (err) {
    console.log("Registration Error:", err);
    res.status(500).send("Server error");
  }
});


//LOGIN 
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Invalid email or password");

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send("Invalid email or password");

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, userId: user._id });

  } catch (err) {
    res.status(500).send("Server error");
  }
});


//ADD PRODUCT
app.post("/api/products", verifyToken, async (req, res) => {
  try {
    const { name, category, description, price, imageUrl, stock } = req.body;

    const product = new Product({
      name,
      category,
      description,
      price,
      imageUrl,
      stock,
      user: req.userId
    });

    await product.save();
    res.status(201).json(product);

  } catch (err) {
    res.status(500).send("Error adding product");
  }
});


//GET LOGGED USER PRODUCTS
app.get("/api/products", verifyToken, async (req, res) => {
  try {
    const products = await Product.find({ user: req.userId });
    res.json(products);
  } catch (err) {
    res.status(500).send("Error fetching products");
  }
});


//UPDATE
app.put("/api/products/:id", verifyToken, async (req, res) => {
  try {
    const updated = await Product.findOneAndUpdate(
      { _id: req.params.id, user: req.userId },
      req.body,
      { new: true }
    );

    if (!updated) return res.status(404).send("Product not found");

    res.json(updated);

  } catch (err) {
    res.status(500).send("Error updating product");
  }
});


// DELETE
app.delete("/api/products/:id", verifyToken, async (req, res) => {
  try {
    const deleted = await Product.findOneAndDelete({
      _id: req.params.id,
      user: req.userId
    });

    if (!deleted) return res.status(404).send("Product not found");

    res.send("Product deleted successfully");

  } catch (err) {
    res.status(500).send("Error deleting product");
  }
});


// START SERVER
app.listen(process.env.PORT || 3001, () => {
  console.log(`🚀 Server running on port ${process.env.PORT}`);
});
