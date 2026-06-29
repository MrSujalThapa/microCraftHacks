export interface FileEntry {
  path: string;
  category: string;
}

export interface InventoryResult {
  totalFiles: number;
  byCategory: Record<string, number>;
  files: FileEntry[];
}

export type StackConfidence = "high" | "medium" | "low";

export interface StackDetection {
  name: string;
  confidence: StackConfidence;
  evidence: string[];
}

export interface SurfaceRoute {
  path: string;
  file: string;
  framework?: string;
}

export interface SurfaceAuth {
  file: string;
  type?: string;
}

export interface SurfaceDataModel {
  file: string;
  name?: string;
}

export interface SurfacesResult {
  routes: SurfaceRoute[];
  api: SurfaceRoute[];
  auth: SurfaceAuth[];
  dataModels: SurfaceDataModel[];
}

export interface ScanReport {
  version: string;
  scannedAt: string;
  projectRoot: string;
  inventory: InventoryResult;
  stack?: StackDetection[];
  surfaces?: SurfacesResult;
}

export interface ScanResult {
  report: ScanReport;
  reportPath: string;
}
