const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());
const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "unauthorized access" });
  }
  //bearer token
  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ error: true, message: "unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.raxgazv.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const usersCollection = client.db("summerClub").collection("users");
    const classesCollection = client.db("summerClub").collection("classes");
    const orderCollection = client.db("summerClub").collection("orders");
    const paymentCollection = client.db("summerClub").collection("payments");

    //to make JWT token
    app.post("/jwt", (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "7d",
      });
      res.send({ token });
    });

    // warning: use verifyJWT before using verifyAdmin
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ error: true, message: "forbidden message" });
      }
      next();
    };
    // warning: use verifyJWT before using verifyInstructor
    const verifyInstructor = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (user?.role !== "instructor") {
        return res
          .status(403)
          .send({ error: true, message: "forbidden message" });
      }
      next();
    };

    //users related apis
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    // to make a user we use post
    app.post("/users", async (req, res) => {
      const user = req.body;
      console.log(user);
      const query = { email: user.email };
      const existingUser = await usersCollection.findOne(query);
      console.log("existing user", existingUser);
      if (existingUser) {
        return res.send({ message: "user already exists" }); // it will happen only for google user//
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    //security layer:verifyJWT, email check, check admin
    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (req.decoded.email !== email) {
        return res.send({ admin: false });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const result = { admin: user?.role === "admin" };
      res.send(result);
    });
    //security layer:verifyJWT, email check, check instructor
    app.get("/users/instructor/:email", verifyJWT, async (req, res) => {
      const email = req.params.email;
      if (req.decoded.email !== email) {
        return res.send({ instructor: false });
      }
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const result = { instructor: user?.role === "instructor" };
      res.send(result);
    });

    // to update partial data then we use patch
    //to change the role
    app.patch("/users/change-role/:id/:role", async (req, res) => {
      const id = req.params.id;
      const role = req.params.role;
      console.log(id);
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: role,
        },
      };
      const result = await usersCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    //to delete an user
    app.delete("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });

    // Retrieve the top 6 classes based on enrollment
    app.get("/classes", async (req, res) => {
      const result = await classesCollection
        .find()
        .sort({ enrolled: -1 })
        .toArray();
      res.send(result);
    });
    // add classes data
    app.post("/classes", verifyJWT, verifyInstructor, async (req, res) => {
      const newItem = req.body;
      const result = await classesCollection.insertOne(newItem);
      res.send(result);
    });

    // update class data
    app.put("/classes/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const body = req.body;
      console.log(body, id);
      const filter = { _id: new ObjectId(id) };

      // Construct the update object dynamically from the body object
      const update = {
        $set: {}, // Initialize the $set operator
      };
      for (const key in body) {
        update.$set[key] = body[key]; // Assign fields to the $set operator
      }

      const result = await classesCollection.updateOne(filter, update, {
        upsert: true,
      });
      console.log(result);
      res.send(result);
    });

    // delete classes data
    app.delete("/classes/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await classesCollection.deleteOne(query);
      res.send(result);
    });

    // orders collection apis
    app.get("/orders", verifyJWT, async (req, res) => {
      // console.log(email)
      const email = req.query.email;
      const paymentStatus = req.query.paymentStatus;
      if (!email) {
        res.send([]);
      }
      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res
          .status(403)
          .send({ error: true, message: "forbidden access" });
      }
      const query = { email: email, paymentStatus: Number(paymentStatus) };
      console.log(query);
      const result = await orderCollection.find(query).toArray();
      res.send(result);
    });

    // orders collection added or updated
    app.post("/orders", async (req, res) => {
      const item = req.body;
      console.log(item);
      const result = await orderCollection.insertOne(item);
      const filter = { _id: new ObjectId(item.classItemId) };
      const updateDoc = {
        $inc: {
          available_seats: -1,
          enrolled: 1,
        },
      };
      const reduceAvailableSeats = await classesCollection.updateOne(
        filter,
        updateDoc
      );
      console.log(reduceAvailableSeats);
      res.send(result);
    });

    //order collection delete
    app.delete("/orders/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await orderCollection.deleteOne(query);
      res.send(result);
    });

    // create payment intent
    app.post("/create-payment-intent", verifyJWT, async (req, res) => {
      const { price } = req.body;
      const amount = parseInt(price * 100);
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: "usd",
        payment_method_types: ["card"],
      });

      res.send({
        clientSecret: paymentIntent.client_secret,
      });
    });
    // payment related api
    app.post("/payments", verifyJWT, async (req, res) => {
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment);
      const updateDoc = {
        $set: {
          paymentStatus: 1,
        },
      };
      const query = {
        _id: { $in: payment.cartItems.map((id) => new ObjectId(id)) },
      };
      const UpdatedPaymentStatus = await orderCollection.updateMany(
        query,
        updateDoc
      );

      res.send({ insertResult, UpdatedPaymentStatus });
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("class is going on");
});

app.listen(port, () => {
  console.log(`class is going on ${port}`);
});
