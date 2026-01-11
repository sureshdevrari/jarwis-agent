import DashboardShell from "./DashboardShell";
import MiftyJarwisLayout from "../layout/MiftyJarwisLayout";
import { featureFlags } from "../../config/features";

// Chooses between the new dashboard shell and the legacy layout via feature flag
const DashboardPageLayout = ({ children }) => {
  const Layout = featureFlags.useNewDashboard ? DashboardShell : MiftyJarwisLayout;
  return <Layout>{children}</Layout>;
};

export default DashboardPageLayout;
