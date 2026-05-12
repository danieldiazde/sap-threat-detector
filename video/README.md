# TPs_data — Hackathon Presentation Video

## Setup
```
cd video && npm install
```

## Preview
```
npm run dev
```
(opens Remotion Studio at localhost:3000)

## Agregar clips de personas
Copia los videos grabados a `video/public/videos/`
con los nombres: `persona1.mp4` ... `persona5.mp4`

## Render final
```
npm run build
```
(output en `video/out/MainVideo.mp4`)

## Scripts en package.json
- `dev`: `remotion studio`
- `build`: `remotion render MainVideo out/MainVideo.mp4`
- `render-preview`: `remotion render MainVideo out/preview.mp4 --scale=0.5 --jpeg-quality=80`
