/**
 * =============================================================================
 * api/graphql_server.js – TigerGate CNAPP Test: Insecure GraphQL API
 * =============================================================================
 * PURPOSE: Demonstrates common GraphQL security vulnerabilities that Tigergate
 * API Security module detects.
 *
 * ⚠️  EDUCATIONAL USE ONLY — Never deploy in production.
 *
 * API SECURITY FINDINGS:
 *   API-001: GraphQL Introspection enabled (information disclosure)
 *   API-002: No query depth limit → Denial of Service via nested queries
 *   API-003: No query complexity limit → Resource exhaustion
 *   API-004: Batching attacks possible (multiple mutations in one request)
 *   API-005: IDOR via user(id:) — returns any user without authorization
 *   API-006: Sensitive fields (password, SSN, creditCard) exposed in schema
 *   API-007: Mutations with no authentication
 *   API-008: No rate limiting on the endpoint
 * =============================================================================
 */

'use strict';

const { ApolloServer, gql } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');

const DB_PASSWORD = 'root123';         // 🔴 Hardcoded credentials!
const JWT_SECRET = 'graphql-super-secret-jwt';  // 🔴 Hardcoded!

// =============================================================================
// 🔴 API-001: INTROSPECTION ENABLED IN PRODUCTION
// Introspection allows anyone to discover the full API schema:
// - All types (User, Order, PaymentCard)
// - All fields (password, ssn, creditCardNumber)
// - All mutations (deleteUser, updatePassword, transferFunds)
// FIX: Disable introspection in production:
//   new ApolloServer({ introspection: false, ... })
// =============================================================================

// =============================================================================
// 🔴 API-006: SENSITIVE FIELDS EXPOSED IN SCHEMA
// A proper schema should never include password, ssn, creditCardNumber
// These should be resolved server-side or use dedicated secure endpoints
// =============================================================================
const typeDefs = gql`
  type Query {
    # 🔴 IDOR: No auth check — any user can get any user's data
    user(id: Int!): User
    # 🔴 No auth — returns all users including their passwords
    users: [User]
    # 🔴 Returns all orders — no ownership check
    orders(userId: Int): [Order]
    # 🔴 Admin data — no authorization requirement
    adminStats: AdminStats
    # Recursive type for DoS
    product(id: Int!): Product
  }

  type Mutation {
    # 🔴 No authentication required for these destructive operations!
    createUser(username: String!, email: String!, password: String!): User
    updateUser(id: Int!, username: String, email: String, role: String): User  # 🔴 Mass assignment!
    deleteUser(id: Int!): Boolean                  # 🔴 Delete ANY user with no auth!
    transferFunds(fromId: Int!, toId: Int!, amount: Float!): Boolean  # 🔴 No auth!
    updatePassword(userId: Int!, newPassword: String!): Boolean       # 🔴 No auth!
  }

  # 🔴 API-006: Sensitive PII fields in public GraphQL schema
  type User {
    id:               Int
    username:         String
    email:            String
    password:         String    # 🔴 CRITICAL: Password hash in schema!
    passwordPlain:    String    # 🔴 CRITICAL: Plain text password field!
    ssn:              String    # 🔴 PII: Social Security Number!
    creditCardNumber: String    # 🔴 PCI-DSS: Full card number!
    cvv:              String    # 🔴 PCI-DSS: CVV MUST NEVER be stored/exposed!
    role:             String    # BAD: Role exposed (useful for attackers)
    # 🔴 API-002: Recursive type allows infinite nesting → DoS
    friends:          [User]    # friends → friends → friends → ... → OOM
    orders:           [Order]
  }

  type Order {
    id:          Int
    userId:      Int
    amount:      Float
    cardLast4:   String
    fullCardNum: String         # 🔴 Full card number in order object!
    cvv:         String         # 🔴 CVV in order object!
    status:      String
    user:        User           # Creates circular reference for DoS
  }

  type Product {
    id:       Int
    name:     String
    price:    Float
    reviews:  [Review]          # Nested type for complexity attacks
  }

  type Review {
    id:      Int
    rating:  Int
    comment: String
    product: Product            # 🔴 Circular: Product → Review → Product → ...
    author:  User               # 🔴 Includes full User with password!
  }

  type AdminStats {
    totalUsers:     Int
    totalRevenue:   Float
    # 🔴 Admin data accessible without authorization
    databaseUrl:    String      # 🔴 Returns DB connection string!
    apiKeys:        [String]    # 🔴 Returns internal API keys!
  }
`;

// Mock data (realistic enough to demonstrate severity)
const users = [
  { id: 1, username: 'admin', email: 'admin@megacorp.com', password: '5f4dcc3b5aa765d61d8327deb882cf99', passwordPlain: 'password', ssn: '123-45-6789', creditCardNumber: '4532015112830366', cvv: '737', role: 'admin' },
  { id: 2, username: 'alice', email: 'alice@megacorp.com', password: '7215ee9c7d9dc229d2921a40e899ec5f', passwordPlain: 'alice123', ssn: '234-56-7890', creditCardNumber: '5425233430109903', cvv: '452', role: 'user' },
  { id: 3, username: 'bob', email: 'bob@example.com', password: '6cb75f652a9b52798eb6cf2201057c73', passwordPlain: 'password1', ssn: '345-67-8901', creditCardNumber: '3714 496353984731', cvv: '0975', role: 'user' },
];

const resolvers = {
  Query: {
    // 🔴 API-005: IDOR — No authorization! Any user can retrieve any other user's data
    user: (_, { id }) => {
      console.log(`[LOG] user(${id}) fetched. No auth check!`);   // Logs every access
      return users.find(u => u.id === id);  // 🔴 IDOR!
    },

    // 🔴 Returns ALL users including passwords, SSNs, credit cards — no auth!
    users: () => {
      console.log(`[LOG] All ${users.length} users returned. Password hashes included!`);
      return users;                         // 🔴 Mass PII disclosure!
    },

    // 🔴 No authorization — any user can see all orders (including other users')
    orders: (_, { userId }) => {
      return [
        { id: 1, userId: 1, amount: 299.99, fullCardNum: '4532015112830366', cvv: '737', status: 'completed' },
        { id: 2, userId: 2, amount: 49.00, fullCardNum: '5425233430109903', cvv: '452', status: 'pending' },
      ].filter(o => !userId || o.userId === userId);
    },

    // 🔴 Admin data with no auth — returns DB URL and API keys
    adminStats: () => ({
      totalUsers: users.length,
      totalRevenue: 50000.00,
      databaseUrl: `mysql://root:${DB_PASSWORD}@mysql:3306/megadb`,  // 🔴 DB URL in response!
      apiKeys: ['sk-prod-AAAA', 'stripe-sk_live_BBBB', JWT_SECRET],  // 🔴 Keys in response!
    }),
  },

  Mutation: {
    // 🔴 No auth — anyone can create users
    createUser: (_, { username, email, password }) => {
      const newUser = { id: users.length + 1, username, email, password, role: 'user' };
      console.log(`[LOG] createUser: password=${password}`);  // 🔴 Password logged!
      users.push(newUser);
      return newUser;
    },

    // 🔴 No auth — anyone can delete any user
    deleteUser: (_, { id }) => {
      console.log(`[LOG] deleteUser(${id}) — no auth check!`);
      const idx = users.findIndex(u => u.id === id);
      if (idx > -1) { users.splice(idx, 1); return true; }
      return false;
    },

    // 🔴 No auth + mass assignment — can change any field including role!
    updateUser: (_, { id, ...updates }) => {
      const user = users.find(u => u.id === id);
      if (user) Object.assign(user, updates);  // 🔴 Mass assignment: role can be set to 'admin'!
      return user;
    },

    // 🔴 No auth — anyone can change anyone's password
    updatePassword: (_, { userId, newPassword }) => {
      const user = users.find(u => u.id === userId);
      if (user) {
        console.log(`[LOG] Password updated for user ${userId}: ${newPassword}`);  // 🔴!
        user.password = newPassword;
        user.passwordPlain = newPassword;
        return true;
      }
      return false;
    },
  },

  // 🔴 API-002: Circular resolver chain — infinite nesting → memory exhaustion
  User: {
    friends: (user) => users.filter(u => u.id !== user.id),  // Returns all other users as "friends"
    orders: (user) => [],
  },
};

// =============================================================================
// 🔴 SERVER CONFIGURATION – Introspection ON, No Depth/Complexity Limits
// =============================================================================
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,           // 🔴 API-001: Schema fully discoverable!
  // 🔴 API-002: No query depth limit (graphql-depth-limit NOT installed)
  // 🔴 API-003: No query complexity limit (graphql-query-complexity NOT installed)
  // 🔴 API-008: No rate limiting middleware applied
  formatError: (err) => ({
    message: err.message,
    stacktrace: err.extensions?.stacktrace,   // 🔴 Stack traces in API errors!
    path: err.path,
  }),
});

startStandaloneServer(server, {
  listen: { port: 4000, host: '0.0.0.0' },   // BAD: Listens on all interfaces
  context: async ({ req }) => ({
    // 🔴 No auth context — token is extracted but never verified!
    token: req.headers.authorization,
    // FIX: Verify JWT token here and set req.user
  }),
}).then(({ url }) => {
  console.log(`GraphQL API at ${url}`);
  console.log(`DB Password: ${DB_PASSWORD}`);   // 🔴 Credentials in startup logs!
});
