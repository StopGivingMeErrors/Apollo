import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { SocProvider } from "../hooks/useSoc.jsx";
import { Shell } from "./Shell";

const Overview = lazy(() => import("./views/Overview"));
const AlertQueue = lazy(() => import("./views/AlertQueue"));
const Investigate = lazy(() => import("./views/Investigate"));
const Cases = lazy(() => import("./views/Cases"));
const Response = lazy(() => import("./views/Response"));
const Metrics = lazy(() => import("./views/Metrics"));

function PageFallback() {
  return <div className="page-fallback">Loading…</div>;
}

export default function App() {
  return (
    <SocProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Shell />}>
            <Route
              index
              element={(
                <Suspense fallback={<PageFallback />}>
                  <Overview />
                </Suspense>
              )}
            />
            <Route
              path="queue"
              element={(
                <Suspense fallback={<PageFallback />}>
                  <AlertQueue />
                </Suspense>
              )}
            />
            <Route
              path="investigate"
              element={(
                <Suspense fallback={<PageFallback />}>
                  <Investigate />
                </Suspense>
              )}
            />
            <Route
              path="cases"
              element={(
                <Suspense fallback={<PageFallback />}>
                  <Cases />
                </Suspense>
              )}
            />
            <Route
              path="response"
              element={(
                <Suspense fallback={<PageFallback />}>
                  <Response />
                </Suspense>
              )}
            />
            <Route
              path="metrics"
              element={(
                <Suspense fallback={<PageFallback />}>
                  <Metrics />
                </Suspense>
              )}
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </SocProvider>
  );
}
