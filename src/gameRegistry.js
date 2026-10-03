import crypto from "node:crypto";
export function playCoin(body){
  const guess=String(body.guess||"").toLowerCase();
  if(!["heads","tails"].includes(guess)) throw new Error("Choose heads or tails");
  const result=crypto.randomInt(0,2)===0?"heads":"tails", win=guess===result;
  return {outcome:result,payoutMultiplier:win?2:0,details:{guess,result,win}};
}
export function playDice(body){
  const guess=Number(body.guess);
  if(!Number.isInteger(guess)||guess<1||guess>6) throw new Error("Choose a number from 1 to 6");
  const result=crypto.randomInt(1,7), win=guess===result;
  return {outcome:String(result),payoutMultiplier:win?6:0,details:{guess,result,win}};
}
export const gameHandlers={"coin-flip":playCoin,"dice-six":playDice};
