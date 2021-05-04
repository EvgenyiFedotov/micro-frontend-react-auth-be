type UserId = string;

type Nonce = {
  token: string;
  created: number;
};

type NonceToLinkId = string;

type NonceToLink = {
  token: string;
  created: number;
};

type User = {
  cid: string;
  password: string;
  nonce: Nonce | null;
  nonceToLinkId: NonceToLinkId | null;
};

const users: Map<UserId, User> = new Map();
const nonceToLinks: Map<NonceToLinkId, NonceToLink> = new Map();

export const hasUser = async (id: UserId): Promise<boolean> => {
  return users.has(id);
};

export const getUser = async (id: UserId): Promise<User> => {
  const user = users.get(id);
  if (user) return user;
  throw new Error("User doesn't exist");
};

export const setUser = async (id: UserId, data: User): Promise<void> => {
  users.set(id, data);
};

export const updateUser = async (id: UserId, data: Partial<User>): Promise<void> => {
  try {
    users.set(id, { ...(await getUser(id)), ...data });
  } catch (error) {
    throw error;
  }
};

export const hasNonceToLink = async (id: NonceToLinkId): Promise<boolean> => {
  return nonceToLinks.has(id);
};

export const getNonceToLink = async (id: NonceToLinkId): Promise<NonceToLink> => {
  const nonceToLink = nonceToLinks.get(id);
  if (nonceToLink) return nonceToLink;
  throw new Error("Nonce to link doesn't exist");
};

export const setNonceToLink = async (id: NonceToLinkId, data: NonceToLink): Promise<void> => {
  nonceToLinks.set(id, data);
};

export const removeNonceToLink = async (id: NonceToLinkId): Promise<void> => {
  nonceToLinks.delete(id);
};
