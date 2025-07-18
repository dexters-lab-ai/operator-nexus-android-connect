import {
  ExtrudeGeometry
} from "./chunk-MYETRLG2.js";
import "./chunk-BUSYA2B4.js";

// node_modules/three/examples/jsm/geometries/TextGeometry.js
var TextGeometry = class extends ExtrudeGeometry {
  /**
   * Constructs a new text geometry.
   *
   * @param {string} text - The text that should be transformed into a geometry.
   * @param {TextGeometry~Options} [parameters] - The text settings.
   */
  constructor(text, parameters = {}) {
    const font = parameters.font;
    if (font === void 0) {
      super();
    } else {
      const shapes = font.generateShapes(text, parameters.size);
      if (parameters.depth === void 0) parameters.depth = 50;
      if (parameters.bevelThickness === void 0) parameters.bevelThickness = 10;
      if (parameters.bevelSize === void 0) parameters.bevelSize = 8;
      if (parameters.bevelEnabled === void 0) parameters.bevelEnabled = false;
      super(shapes, parameters);
    }
    this.type = "TextGeometry";
  }
};
export {
  TextGeometry
};
//# sourceMappingURL=three_examples_jsm_geometries_TextGeometry__js.js.map
