const { graphql, buildSchema } = require('graphql');

// Vulnerable GraphQL Schema demonstrating Introspection and missing Depth Limits
var schema = buildSchema(`
  type Query {
    hello: String
    user(id: Int!): User
  }
  type User {
    id: Int
    name: String
    friends: [User]
  }
`);

// The "friends" relation allows recursively asking for friends of friends of friends infinitely.
// TigerGate API Security will flag this for missing depth limits.
var root = {
    hello: () => 'Hello world!',
    user: ({ id }) => {
        return { id: id, name: "Alice", friends: [{ id: 2, name: "Bob" }] };
    }
};
// TigerGate should flag that introspection queries are enabled by default
