import { useEffect, useRef } from "react";
import * as THREE from "three";

type SupplyChainSceneProps = {
  progress: number;
};

export function SupplyChainScene({ progress }: SupplyChainSceneProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const progressRef = useRef(progress);

  useEffect(() => {
    progressRef.current = progress;
  }, [progress]);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0f1720, 10, 30);

    const camera = new THREE.PerspectiveCamera(45, mount.clientWidth / Math.max(mount.clientHeight, 1), 0.1, 100);
    camera.position.set(0, 2, 15);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(mount.clientWidth, mount.clientHeight);
    renderer.setClearColor(0x000000, 0);
    mount.appendChild(renderer.domElement);

    const ambient = new THREE.AmbientLight(0xffffff, 0.65);
    const keyLight = new THREE.PointLight(0x6de7d7, 3.8, 60);
    keyLight.position.set(6, 8, 10);
    const warnLight = new THREE.PointLight(0xff8f6b, 3.1, 50);
    warnLight.position.set(-7, -2, 8);
    scene.add(ambient, keyLight, warnLight);

    const nodes = [
      new THREE.Vector3(-7, 1.2, 0),
      new THREE.Vector3(-4.2, -1.3, 1.2),
      new THREE.Vector3(-0.8, 1.1, -0.2),
      new THREE.Vector3(2.3, -0.8, 0.8),
      new THREE.Vector3(5.4, 1, -0.6),
    ];

    const nodeMeshes = nodes.map((position, index) => {
      const geometry = new THREE.IcosahedronGeometry(index === nodes.length - 1 ? 1.15 : 0.8, 1);
      const material = new THREE.MeshPhysicalMaterial({
        color: index >= 3 ? 0xff8f6b : 0x6de7d7,
        emissive: index >= 3 ? 0x3b1209 : 0x072d2a,
        roughness: 0.25,
        metalness: 0.15,
        transparent: true,
        opacity: 0.95,
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.copy(position);
      scene.add(mesh);
      return mesh;
    });

    const lineMaterial = new THREE.LineBasicMaterial({ color: 0x6de7d7, transparent: true, opacity: 0.45 });
    const linePoints = nodes.flatMap((point, index) => (index < nodes.length - 1 ? [point, nodes[index + 1]] : []));
    const lineGeometry = new THREE.BufferGeometry().setFromPoints(linePoints);
    const connections = new THREE.LineSegments(lineGeometry, lineMaterial);
    scene.add(connections);

    const attackerGeometry = new THREE.SphereGeometry(0.24, 18, 18);
    const attackerMaterial = new THREE.MeshBasicMaterial({ color: 0xffa07d });
    const attackerPulse = new THREE.Mesh(attackerGeometry, attackerMaterial);
    scene.add(attackerPulse);

    const shieldGeometry = new THREE.TorusGeometry(1.75, 0.06, 20, 60);
    const shieldMaterial = new THREE.MeshBasicMaterial({ color: 0x6de7d7, transparent: true, opacity: 0.85 });
    const shieldRing = new THREE.Mesh(shieldGeometry, shieldMaterial);
    shieldRing.rotation.x = Math.PI / 2;
    shieldRing.position.copy(nodes[nodes.length - 1]);
    scene.add(shieldRing);

    const particles = new THREE.Group();
    for (let index = 0; index < 26; index += 1) {
      const particle = new THREE.Mesh(
        new THREE.SphereGeometry(0.04 + Math.random() * 0.05, 8, 8),
        new THREE.MeshBasicMaterial({ color: index % 2 === 0 ? 0x6de7d7 : 0xff8f6b, transparent: true, opacity: 0.55 }),
      );
      particle.position.set(
        (Math.random() - 0.5) * 14,
        (Math.random() - 0.5) * 7,
        (Math.random() - 0.5) * 6,
      );
      particles.add(particle);
    }
    scene.add(particles);

    const pathCurve = new THREE.CatmullRomCurve3(nodes);
    const clock = new THREE.Clock();
    let frameId = 0;

    const resize = () => {
      if (!mount) return;
      camera.aspect = mount.clientWidth / Math.max(mount.clientHeight, 1);
      camera.updateProjectionMatrix();
      renderer.setSize(mount.clientWidth, mount.clientHeight);
    };

    const animate = () => {
      const elapsed = clock.getElapsedTime();
      const storyProgress = progressRef.current;

      nodeMeshes.forEach((mesh, index) => {
        mesh.rotation.x += 0.003 + index * 0.0007;
        mesh.rotation.y += 0.004 + index * 0.0009;
        mesh.position.y = nodes[index].y + Math.sin(elapsed * 0.8 + index * 0.8) * 0.12;
        const scaleBump = index <= Math.floor(storyProgress * (nodes.length - 1)) ? 1.08 : 1;
        mesh.scale.setScalar(scaleBump);
      });

      const attackTravel = (elapsed * 0.12 + storyProgress * 0.88) % 1;
      attackerPulse.position.copy(pathCurve.getPoint(attackTravel));

      shieldRing.scale.setScalar(1 + Math.sin(elapsed * 2.4 + storyProgress * 4) * 0.05);
      shieldRing.material.opacity = 0.5 + storyProgress * 0.35;

      connections.material.opacity = 0.3 + storyProgress * 0.35;
      particles.rotation.y = elapsed * 0.05;
      particles.rotation.x = elapsed * 0.03;

      camera.position.x = Math.sin(storyProgress * Math.PI) * 2.6;
      camera.position.y = 1.8 - storyProgress * 1.1;
      camera.position.z = 15 - storyProgress * 3.4;
      camera.lookAt(0, 0, 0);

      renderer.render(scene, camera);
      frameId = window.requestAnimationFrame(animate);
    };

    resize();
    animate();
    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
      window.cancelAnimationFrame(frameId);
      renderer.dispose();
      nodeMeshes.forEach((mesh) => {
        mesh.geometry.dispose();
        (mesh.material as THREE.Material).dispose();
      });
      attackerGeometry.dispose();
      attackerMaterial.dispose();
      shieldGeometry.dispose();
      shieldMaterial.dispose();
      lineGeometry.dispose();
      lineMaterial.dispose();
      particles.children.forEach((child: THREE.Object3D) => {
        const mesh = child as THREE.Mesh;
        mesh.geometry.dispose();
        (mesh.material as THREE.Material).dispose();
      });
      mount.removeChild(renderer.domElement);
    };
  }, []);

  return <div className="supply-chain-canvas" ref={mountRef} />;
}
