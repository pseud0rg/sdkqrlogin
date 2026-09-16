import { createInMemoryWebLoginRepository } from "@pseud0/web-login-node";
import { defineWebLoginRepositoryContract } from "../src/index.js";

defineWebLoginRepositoryContract(async () => createInMemoryWebLoginRepository({ testsOnly: true }));
