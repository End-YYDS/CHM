import axios from "axios";
import { api } from "../../chm.config";

const axiosInstance = axios.create({
    baseURL: api,
    timeout: 10000,
    headers: {
        "Content-Type": "application/json",
    },
});

axiosInstance.interceptors.response.use(
    (response) => {
        if (response.data && response.data.data) {
            return response.data.data;
        }
        return response.data;
    },
    (error) => {
        console.error(error);
        return Promise.reject(error);
    }
);

export default axiosInstance;
