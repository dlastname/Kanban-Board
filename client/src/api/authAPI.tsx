import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  // xTODO: make a POST request to the login route
  try {
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(userInfo),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error("User information not found, check network tab");
    }
    console.log(data);
    
    return data;
  } catch (err) {
    console.log("Error from user login api", err);
    return Promise.reject("Could not fetch user info");
  }
};

export { login };