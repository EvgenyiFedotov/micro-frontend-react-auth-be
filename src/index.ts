import express from "express";
import * as http from "http";
import bcrypt from "bcrypt";
import Fingerprint from 'express-fingerprint';
import * as FingerprintParams from "express-fingerprint/lib/parameters";
import requestIp from "request-ip";
import cookieParser from "cookie-parser";

import { getUser, hasUser, setNonceToLink, setUser, updateUser } from "./users";

const SALT_ROUNDS = 10;
const NONCE_TOKEN_BORDER = 1000 * 60 * 2;
const COOKIE_NONCE_TOKEN_KEY = 'nonceToken';
const port = process.env.PORT;
const app = express();

const server = http.createServer(app);

app.use(cookieParser());
app.use(express.json());
app.use(requestIp.mw());
app.use(Fingerprint({
  parameters:[
    FingerprintParams.useragent,
    FingerprintParams.acceptHeaders,
    async (_next, _req, _res) => {
      const next: any = _next;
      const req: any = _req;
      const res: any = _res;

      let cid = req.cookies.cid;

      if (!req.cookies.cid) {
        const cid = await bcrypt.genSalt(SALT_ROUNDS);
        res.cookie('cid', cid);
      }

      next(null, { cid });
    },
  ],
}));

const getHash =  async (req: express.Request) => {
  return req.fingerprint?.hash ?? "";
};

const clearNonceToken = async (req: express.Request, res: express.Response) => {
  const hash = await getHash(req);

  if (await hasUser(hash)) {
    res.clearCookie(COOKIE_NONCE_TOKEN_KEY);
    await updateUser(hash, { nonce: null });
  }
};

const getUserByReq = async (req: express.Request) => {
  const hash = await getHash(req);
  return await hasUser(hash) ? await getUser(hash) : null;
};

const checkAccess = async (req: express.Request) => {
  const hash = await getHash(req);
  const user = await getUserByReq(req);
  const nonceToken = req.cookies.nonceToken;
  let error: null | string = null;

  if (!hash) {
    error = "Hash doesn't exist";
  } else if (!Boolean(nonceToken)) {
    error = "Nonce token doesn't exist";
  } else if (!Boolean(user) || !user?.nonce?.token) {
    error = "User doesn't exist";
  } else if (nonceToken !== user?.nonce?.token) {
    error = "Nonce is incorrect";
  } else if (new Date().getTime() > user.nonce.created + NONCE_TOKEN_BORDER) {
    error = "Nonce is old";
  }

  return error;
};

const getStatusByAccess = async (req: express.Request) => {
  let status: number = 200;

  if (await checkAccess(req)) {
    status = 401;
  } else if (!await getHash(req) || !await getUserByReq(req)) {
    status = 400;
  }

  return status;
};

app.get("/api/check-access", async (req, res) => {
  const status = await getStatusByAccess(req);

  if (status === 401) {
    await clearNonceToken(req, res);
  }

  res.status(status);
  res.end();
});

app.post("/api/sign-in", async (req, res) => {
  const password: string = req.body?.password.trim() ?? "";
  const hash = await getHash(req);
  const user = await getUserByReq(req);
  let status: number = 200;

  if (!hash || !password) {
    status = 400;
  } else if (user && !await bcrypt.compare(password, user.password)) {
    status = 401;
  }

  if (status === 200 && !user) {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const token = await bcrypt.genSalt(SALT_ROUNDS);

    setUser(hash, {
      cid: req.cookies.cid,
      password: await bcrypt.hash(password, salt),
      nonce: { token, created: new Date().getTime() },
      nonceToLinkId: null,
    });
    res.cookie(COOKIE_NONCE_TOKEN_KEY, token);
  } else if (status === 200 && user) {
    const token = await bcrypt.genSalt(SALT_ROUNDS);

    updateUser(hash, {
      nonce: { token, created: new Date().getTime() },
    });
    res.cookie(COOKIE_NONCE_TOKEN_KEY, token);
  } else if (status === 401) {
    await clearNonceToken(req, res);
  }

  res.status(status);
  res.end();
});

app.post("/api/sign-out", async (req, res) => {
  let status: number = await getStatusByAccess(req);

  if (status === 200) {
    await clearNonceToken(req, res);
  }

  res.status(status);
  res.end();
});

app.get("/api/link/:nonceToLinkId", async (req, res) => {
  const { nonceToLinkId } = req.params;
  let status: number = await getStatusByAccess(req);

  if (!nonceToLinkId) {
    status = 400;
  }

  if (status === 401) {
    await clearNonceToken(req, res);
  } else if (status === 200) {
    updateUser(await getHash(req), { nonceToLinkId: null });
  }

  res.status(status);
  res.end();
});

app.get("/api/nonce-to-link", async (req, res) => {
  const { hash } = req.fingerprint ?? { hash: "" };
  const user = await hasUser(hash) ? await getUser(hash) : null;
  let status: number = 200;

  if (!hash || !user) {
    status = 400;
  } else if (!user.nonce) {
    status = 401;
  }

  if (status === 401) {
    await clearNonceToken(req, res);
  } else if (status === 200) {
    const nonceToLinkId = await bcrypt.genSalt(SALT_ROUNDS);

    setNonceToLink(nonceToLinkId, {
      token: await bcrypt.genSalt(SALT_ROUNDS),
      created: new Date().getTime(),
    });
    updateUser(hash, { nonceToLinkId });
  }

  res.status(status);
  res.end();
});

app.get("*", (_, res) => {
  res.send("Server app");
  res.end();
});

server.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
