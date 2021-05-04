type UserId = string;

type User = {
  cid: string;
  password: string;
  nonceToken: string | null;
  nonceCreated: number | null;
  linkToken: string | null;
  linkTokenShort: string | null;
  linkCreated: number | null;
  linkedUsers: { cid: string }[];
};

const users: Map<UserId, User> = new Map();

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

export const findUserByLinkTokenShort = async (linkTokenShort: string): Promise<User | null> => {
  return Array.from(users.values()).filter((user) => user.linkTokenShort === linkTokenShort)[0] || null;
};
