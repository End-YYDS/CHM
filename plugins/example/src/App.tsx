import "./index.css";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import axiosInstance from "@/lib/axios_instance";
function App() {
    const [data, setData] = useState({ a: 0, b: 0 });
    const add = async () => {
        if (data.a == 0 || data.b == 0) {
            return;
        }
        try {
            const response = await axiosInstance.post("add", data);
            console.log(response);
        } catch (e) {
            console.log(e);
        }
    };
    const sub = async () => {
        if (data.a == 0 || data.b == 0) {
            return;
        }
        try {
            const response = await axiosInstance.post("sub", data);
            console.log(response);
        } catch (e) {
            console.log(e);
        }
    };

    return (
        <div>
            <input
                type="number"
                value={data.a}
                placeholder="A number"
                onChange={(e) =>
                    setData({ ...data, a: Number(e.target.value) })
                }
            />
            <input
                type="number"
                value={data.b}
                placeholder="B number"
                onChange={(e) =>
                    setData({ ...data, b: Number(e.target.value) })
                }
            />
            <Button
                className="tw:border-2 tw:border-blue-500 tw:bg-blue-500 tw:text-white tw:px-4 tw:py-2 tw:rounded"
                onClick={add}
            >
                Add
            </Button>
            <Button
                className="tw:border-2 tw:border-blue-500 tw:bg-blue-500 tw:text-white tw:px-4 tw:py-2 tw:rounded"
                onClick={sub}
            >
                Sub
            </Button>
        </div>
    );
}

export default App;
