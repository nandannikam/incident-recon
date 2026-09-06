import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";

// No StrictMode: its dev-only double-mounting trips React Flow's nodeTypes
// false-positive warning on every graph mount. Not worth the console noise
// for an exhibition demo.
createRoot(document.getElementById("root")!).render(<App />);
